<?php
/*
Plugin Name: Tiny 2FA
Plugin URI: https://github.com/webguyio/tiny-2fa
Description: A simple two-factor authentication plugin that just works.
Version: 0.2
Requires at least: 5.0
Requires PHP: 7.4
Author: Web Guy
Author URI: https://webguy.io/
License: CC0
License URI: https://creativecommons.org/public-domain/cc0/
Text Domain: tiny-2fa
*/

if ( !defined( 'ABSPATH' ) ) {
	status_header( 404 );
	exit;
}

class Tiny_2FA {
	private $tiny_2fa_encryption_key;

	public function __construct() {
		add_action( 'show_user_profile', array( $this, 'tiny_2fa_render_profile_fields' ) );
		add_action( 'edit_user_profile', array( $this, 'tiny_2fa_render_profile_fields' ) );
		add_action( 'personal_options_update', array( $this, 'tiny_2fa_save_profile_settings' ) );
		add_action( 'edit_user_profile_update', array( $this, 'tiny_2fa_save_profile_settings' ) );
		add_action( 'login_form', array( $this, 'tiny_2fa_render_login_field' ) );
		add_action( 'wp_login', array( $this, 'tiny_2fa_clear_login_attempts' ), 10, 2 );
		add_filter( 'authenticate', array( $this, 'tiny_2fa_check_brute_force' ), 20, 3 );
		add_filter( 'authenticate', array( $this, 'tiny_2fa_validate_login' ), 30, 3 );
		$this->tiny_2fa_encryption_key = $this->tiny_2fa_get_encryption_key();
	}

	private function tiny_2fa_get_encryption_key() {
		$key = get_site_option( 'tiny_2fa_encryption_key' );
		if ( !$key ) {
			$key = bin2hex( random_bytes( 32 ) );
			update_site_option( 'tiny_2fa_encryption_key', $key );
		}
		return $key;
	}

	private function tiny_2fa_encrypt_secret_key( $secret_key ) {
		$nonce = random_bytes( 12 );
		$tag   = '';
		$encrypted = openssl_encrypt( $secret_key, 'aes-256-gcm', $this->tiny_2fa_encryption_key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16 );
		return base64_encode( $nonce . $tag . $encrypted );
	}

	private function tiny_2fa_decrypt_secret_key( $encrypted_key ) {
		$decoded = base64_decode( $encrypted_key );
		$nonce   = substr( $decoded, 0, 12 );
		$tag     = substr( $decoded, 12, 16 );
		$ciphertext = substr( $decoded, 28 );
		return openssl_decrypt( $ciphertext, 'aes-256-gcm', $this->tiny_2fa_encryption_key, OPENSSL_RAW_DATA, $nonce, $tag );
	}

	private function tiny_2fa_generate_secret_key() {
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret = '';
		for ( $i = 0; $i < 32; $i++ ) {
			$secret .= $chars[ random_int( 0, 31 ) ];
		}
		return $secret;
	}

	private function tiny_2fa_generate_qr_code( $secret_key, $username ) {
		$qr_data = sprintf( 'otpauth://totp/2FA:?secret=%s&issuer=2FA', rawurlencode( $secret_key ) );
		$cloudflare_worker_url = 'https://qr.2fas.workers.dev/';
		$qr_url = sprintf( '%s?text=%s&size=200', $cloudflare_worker_url, rawurlencode( $qr_data ) );
		return esc_url( $qr_url );
	}

	private function tiny_2fa_base32_decode( $secret ) {
		$base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret = strtoupper( $secret );
		$buffer = 0;
		$bufferLength = 0;
		$output = '';
		foreach ( str_split( $secret ) as $char ) {
			$buffer = ( $buffer << 5 ) | strpos( $base32chars, $char );
			$bufferLength += 5;
			if ( $bufferLength >= 8 ) {
				$bufferLength -= 8;
				$output .= chr( ( $buffer & ( 0xFF << $bufferLength ) ) >> $bufferLength );
			}
		}
		return $output;
	}

	private function tiny_2fa_calculate_totp_code( $secret, $timestamp ) {
		$secret_decoded = $this->tiny_2fa_base32_decode( $secret );
		$time_step = floor( $timestamp / 30 );
		$binary_time = pack( 'N*', 0 ) . pack( 'N*', $time_step );
		$hmac = hash_hmac( 'sha1', $binary_time, $secret_decoded, true );
		$offset = ord( $hmac[19] ) & 0xf;
		$code = (
			( ( ord( $hmac[ $offset ] ) & 0x7f ) << 24 ) |
			( ( ord( $hmac[ $offset + 1 ] ) & 0xff ) << 16 ) |
			( ( ord( $hmac[ $offset + 2 ] ) & 0xff ) << 8 ) |
			( ord( $hmac[ $offset + 3 ] ) & 0xff )
		);
		return substr( (string) ( $code % 1000000 ), -6, 6 );
	}

	private function tiny_2fa_verify_totp_code( $secret, $code ) {
		if ( !preg_match( '/^\d{6}$/', $code ) ) {
			return false;
		}
		$time = time();
		for ( $i = -1; $i <= 1; $i++ ) {
			$calculated_code = $this->tiny_2fa_calculate_totp_code( $secret, $time + ( $i * 30 ) );
			if ( hash_equals( $calculated_code, $code ) ) {
				return true;
			}
		}
		return false;
	}

	public function tiny_2fa_check_brute_force( $user, $username, $password ) {
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}
		$brute_force_enabled = get_site_option( 'tiny_2fa_brute_force_enabled', '1' );
		if ( $brute_force_enabled !== '1' ) {
			return $user;
		}
		$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
		$transient_key = 'login_attempts_' . md5( $ip );
		$attempts = get_transient( $transient_key );
		if ( !$attempts ) {
			$attempts = array();
		}
		$current_time = time();
		$attempts = array_filter( $attempts, function( $timestamp ) use ( $current_time ) {
			return ( $current_time - $timestamp ) < DAY_IN_SECONDS;
		} );
		if ( count( $attempts ) >= 10 ) {
			return new WP_Error( 'too_many_attempts', __( 'Too many failed login attempts. Please try again later.', 'tiny-2fa' ) );
		}
		if ( is_wp_error( $user ) ) {
			$attempts[] = $current_time;
			set_transient( $transient_key, $attempts, DAY_IN_SECONDS );
		}
		return $user;
	}

	public function tiny_2fa_clear_login_attempts( $user_login, $user ) {
		$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
		$transient_key = 'login_attempts_' . md5( $ip );
		delete_transient( $transient_key );
	}

	public function tiny_2fa_render_profile_fields( $user ) {
		if ( !current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		wp_nonce_field( 'tiny_2fa_profile_nonce', 'tiny_2fa_profile_nonce' );
		$is_admin = current_user_can( 'manage_options' );
		$brute_force_enabled = get_site_option( 'tiny_2fa_brute_force_enabled', '1' );
		$two_factor_enabled = get_user_meta( $user->ID, 'tiny_2fa_enabled', true );
		$two_factor_email_enabled = get_user_meta( $user->ID, 'tiny_2fa_email_enabled', true );
		$two_factor_email_enabled = $two_factor_email_enabled === '' ? '1' : $two_factor_email_enabled;
		$encrypted_secret_key = get_user_meta( $user->ID, 'tiny_2fa_secret_key', true );
		if ( $two_factor_enabled && empty( $encrypted_secret_key ) ) {
			$secret_key = $this->tiny_2fa_generate_secret_key();
			$encrypted_secret_key = $this->tiny_2fa_encrypt_secret_key( $secret_key );
			update_user_meta( $user->ID, 'tiny_2fa_secret_key', $encrypted_secret_key );
		}
		?>
		<h2 id="2fa"><?php esc_html_e( 'Two-Factor Authentication', 'tiny-2fa' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><label for="tiny_2fa_enabled"><?php esc_html_e( 'Enable 2FA', 'tiny-2fa' ); ?></label></th>
				<td><label><input type="checkbox" name="tiny_2fa_enabled" id="tiny_2fa_enabled" value="1" <?php checked( $two_factor_enabled, '1' ); ?>>
				<?php esc_html_e( 'Enable two-factor authentication for your account.', 'tiny-2fa' ); ?></label></td>
			</tr>
			<?php if ( $two_factor_enabled ) : $secret_key = $this->tiny_2fa_decrypt_secret_key( $encrypted_secret_key ); ?>
				<tr>
					<th><label for="tiny_2fa_email_enabled"><?php esc_html_e( 'Backup Codes', 'tiny-2fa' ); ?></label></th>
					<td><label><input type="checkbox" name="tiny_2fa_email_enabled" id="tiny_2fa_email_enabled" value="1" <?php checked( $two_factor_email_enabled, '1' ); ?>>
					<?php esc_html_e( 'Receive backup codes by email. You should disable this once you confirm you can log in with your authenticator app.', 'tiny-2fa' ); ?></label></td>
				</tr>
				<tr>
					<th><label><?php esc_html_e( 'Secret Key', 'tiny-2fa' ); ?></label></th>
					<td><img src="<?php echo esc_attr( $this->tiny_2fa_generate_qr_code( $secret_key, $user->user_login ) ); ?>" alt="<?php esc_attr_e( 'Scan with Authenticator App', 'tiny-2fa' ); ?>" style="max-width:200px;height:auto"><br>
					<input type="text" id="tiny-2fa-secret-key" value="<?php echo esc_attr( $secret_key ); ?>" readonly class="regular-text"><br>
					<?php esc_html_e( 'Scan QR code or manually enter the secret key into your authenticator app.', 'tiny-2fa' ); ?></td>
				</tr>
			<?php endif; ?>
			<?php if ( $is_admin ) : ?>
			<tr>
				<th><label for="tiny_2fa_brute_force_enabled"><?php esc_html_e( 'Brute Force Protection', 'tiny-2fa' ); ?></label></th>
				<td><label><input type="checkbox" name="tiny_2fa_brute_force_enabled" id="tiny_2fa_brute_force_enabled" value="1" <?php checked( $brute_force_enabled, '1' ); ?>>
				<?php esc_html_e( 'Enable brute force protection (blocks IPs after 10 failed login attempts for 24 hours).', 'tiny-2fa' ); ?></label></td>
			</tr>
			<?php endif; ?>
		</table>
		<?php
	}

	public function tiny_2fa_save_profile_settings( $user_id ) {
		if ( !isset( $_POST['tiny_2fa_profile_nonce'] ) || !wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['tiny_2fa_profile_nonce'] ) ), 'tiny_2fa_profile_nonce' ) ) {
			return;
		}
		if ( !current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		if ( current_user_can( 'manage_options' ) ) {
			$brute_force_enabled = isset( $_POST['tiny_2fa_brute_force_enabled'] ) ? '1' : '0';
			update_site_option( 'tiny_2fa_brute_force_enabled', $brute_force_enabled );
		}
		$previous_2fa_status = get_user_meta( $user_id, 'tiny_2fa_enabled', true );
		$two_factor_enabled = isset( $_POST['tiny_2fa_enabled'] ) ? '1' : '0';
		if ( $two_factor_enabled && !$previous_2fa_status ) {
			$two_factor_email_enabled = '1';
		} else {
			$two_factor_email_enabled = isset( $_POST['tiny_2fa_email_enabled'] ) ? '1' : '0';
		}
		update_user_meta( $user_id, 'tiny_2fa_enabled', $two_factor_enabled );
		update_user_meta( $user_id, 'tiny_2fa_email_enabled', $two_factor_email_enabled );
		if ( $two_factor_enabled && !$previous_2fa_status ) {
			add_filter( 'wp_redirect', function( $location ) {
				return $location . '#2fa';
			} );
		}
		if ( !$two_factor_enabled ) {
			delete_user_meta( $user_id, 'tiny_2fa_secret_key' );
		}
	}

	public function tiny_2fa_render_login_field() {
		?>
		<p class="user-2fa-wrap">
			<label for="user_2fa"><?php esc_html_e( 'Two-Factor Authentication Code', 'tiny-2fa' ); ?></label>
			<input type="text" name="user_2fa" id="user_2fa" class="input" placeholder="<?php esc_attr_e( '2FA users only', 'tiny-2fa' ); ?>" autocomplete="off">
		</p>
		<?php
	}

	public function tiny_2fa_validate_login( $user, $username, $password ) {
		if ( is_wp_error( $user ) || empty( $username ) ) {
			return $user;
		}
		$two_factor_enabled = get_user_meta( $user->ID, 'tiny_2fa_enabled', true );
		if ( !$two_factor_enabled ) {
			return $user;
		}
		if ( !wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			return $user;
		}
		if ( !isset( $_POST['user_2fa'] ) ) {
			return new WP_Error( 'two_factor_required', __( 'Two-factor authentication code is required.', 'tiny-2fa' ) );
		}
		$submitted_code = sanitize_text_field( wp_unslash( $_POST['user_2fa'] ) );
		$encrypted_secret_key = get_user_meta( $user->ID, 'tiny_2fa_secret_key', true );
		$secret_key = $this->tiny_2fa_decrypt_secret_key( $encrypted_secret_key );
		$calculated_code = $this->tiny_2fa_calculate_totp_code( $secret_key, time() );
		$two_factor_email_enabled = get_user_meta( $user->ID, 'tiny_2fa_email_enabled', true );
		$two_factor_email_enabled = $two_factor_email_enabled === '' ? '1' : $two_factor_email_enabled;
		if ( $two_factor_email_enabled ) {
			$this->tiny_2fa_send_email( $user, $calculated_code );
		}
		if ( !$this->tiny_2fa_verify_totp_code( $secret_key, $submitted_code ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
			$transient_key = 'login_attempts_' . md5( $ip );
			$attempts = get_transient( $transient_key );
			if ( !$attempts ) {
				$attempts = array();
			}
			$current_time = time();
			$attempts = array_filter( $attempts, function( $timestamp ) use ( $current_time ) {
				return ( $current_time - $timestamp ) < DAY_IN_SECONDS;
			} );
			$attempts[] = $current_time;
			set_transient( $transient_key, $attempts, DAY_IN_SECONDS );
			return new WP_Error( 'invalid_2fa_code', __( 'Invalid two-factor authentication code.', 'tiny-2fa' ) );
		}
		return $user;
	}

	private function tiny_2fa_send_email( $user, $code ) {
		$to = sanitize_email( $user->user_email );
		$site = sanitize_text_field( get_bloginfo( 'name' ) );
		$subject = sprintf( '[%s] 2FA Code', $site );
		$message = sanitize_text_field( $code );
		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );
		return wp_mail( $to, $subject, $message, $headers );
	}
}

new Tiny_2FA();