<?php
/*
Plugin Name: Tiny 2FA
Plugin URI: https://github.com/webguyio/tiny-2fa
Description: A simple two-factor authentication plugin that just works.
Version: 0.4
Requires at least: 6.0
Requires PHP: 8.0
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

	// ========================================
	// INITIALIZATION
	// ========================================

	public function __construct() {
		// Initialization
		$this->tiny_2fa_encryption_key = $this->tiny_2fa_get_encryption_key();
		// User Profile & Settings
		add_action( 'show_user_profile', array( $this, 'tiny_2fa_render_profile_fields' ) );
		add_action( 'edit_user_profile', array( $this, 'tiny_2fa_render_profile_fields' ) );
		add_action( 'personal_options_update', array( $this, 'tiny_2fa_save_profile_settings' ) );
		add_action( 'edit_user_profile_update', array( $this, 'tiny_2fa_save_profile_settings' ) );
		add_action( 'admin_init', array( $this, 'tiny_2fa_handle_regenerate' ) );
		// Login & Authentication
		add_action( 'login_form', array( $this, 'tiny_2fa_render_login_field' ) );
		add_filter( 'authenticate', array( $this, 'tiny_2fa_validate_login' ), 30, 3 );
		// Brute Force Protection
		add_filter( 'authenticate', array( $this, 'tiny_2fa_check_brute_force' ), 20, 3 );
		add_action( 'wp_login', array( $this, 'tiny_2fa_clear_login_attempts' ), 10, 2 );
	}

	// ========================================
	// ENCRYPTION KEY MANAGEMENT
	// ========================================

	private function tiny_2fa_manage_backup_key( $action = 'load', $key = null ) {
		$file_path = WP_CONTENT_DIR . '/tiny-2fa-backup.php';
		if ( $action === 'save' && $key ) {
			$content = "<?php\n// Tiny 2FA Encryption Key Backup\n// Do not edit or delete this file\nif ( !defined( 'ABSPATH' ) ) { exit; }\nreturn '" . $key . "';\n";
			return file_put_contents( $file_path, $content, LOCK_EX ) !== false; // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- Intentionally writing to WP_CONTENT_DIR, not the plugin folder.
		}
		if ( $action === 'load' && file_exists( $file_path ) ) {
			return include $file_path;
		}
		return false;
	}

	private function tiny_2fa_get_encryption_key() {
		if ( defined( 'TINY_2FA_ENCRYPTION_KEY' ) && TINY_2FA_ENCRYPTION_KEY ) {
			$key = TINY_2FA_ENCRYPTION_KEY;
			if ( strlen( $key ) === 64 && ctype_xdigit( $key ) ) {
				$this->tiny_2fa_manage_backup_key( 'save', $key );
				return hex2bin( $key );
			}
		}
		$key = get_site_option( 'tiny_2fa_encryption_key' );
		if ( !$key ) {
			$key = $this->tiny_2fa_manage_backup_key( 'load' );
			if ( $key ) {
				update_site_option( 'tiny_2fa_encryption_key', $key );
			}
		}
		if ( !$key ) {
			$key = bin2hex( random_bytes( 32 ) );
			$added = add_site_option( 'tiny_2fa_encryption_key', $key );
			if ( !$added ) {
				$key = get_site_option( 'tiny_2fa_encryption_key' );
				if ( !$key ) {
					wp_die( esc_html__( 'Critical error: Unable to save encryption key.', 'tiny-2fa' ) );
				}
			} else {
				$backup_saved = $this->tiny_2fa_manage_backup_key( 'save', $key );
				if ( !$backup_saved ) {
					wp_die( esc_html__( 'Critical error: Unable to save encryption key backup.', 'tiny-2fa' ) );
				}
			}
		} else {
			$this->tiny_2fa_manage_backup_key( 'save', $key );
		}
		return hex2bin( $key );
	}

	// ========================================
	// TOTP SECRET KEY OPERATIONS
	// ========================================

	private function tiny_2fa_encrypt_secret_key( $secret_key ) {
		$nonce = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
		$encrypted = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
			$secret_key,
			'',
			$nonce,
			$this->tiny_2fa_encryption_key
		);
		return base64_encode( $nonce . $encrypted );
	}

	private function tiny_2fa_decrypt_secret_key( $encrypted_key ) {
		$decoded = base64_decode( $encrypted_key );
		$nonce = substr( $decoded, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
		$ciphertext = substr( $decoded, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
		return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
			$ciphertext,
			'',
			$nonce,
			$this->tiny_2fa_encryption_key
		);
	}

	private function tiny_2fa_generate_secret_key() {
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret = '';
		for ( $i = 0; $i < 32; $i++ ) {
			$secret .= $chars[ random_int( 0, 31 ) ];
		}
		return $secret;
	}

	// ========================================
	// TOTP CODE GENERATION & VERIFICATION
	// ========================================

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
		return str_pad( (string) ( $code % 1000000 ), 6, '0', STR_PAD_LEFT );
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

	// ========================================
	// USER PROFILE & SETTINGS
	// ========================================

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
		?>
		<h2 id="2fa"><?php esc_html_e( 'Two-Factor Authentication', 'tiny-2fa' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><label for="tiny_2fa_enabled"><?php esc_html_e( 'Enable 2FA', 'tiny-2fa' ); ?></label></th>
				<td><label><input type="checkbox" name="tiny_2fa_enabled" id="tiny_2fa_enabled" value="1" <?php checked( $two_factor_enabled, '1' ); ?>>
				<?php esc_html_e( 'Enable two-factor authentication for your account.', 'tiny-2fa' ); ?></label></td>
			</tr>
			<?php if ( $two_factor_enabled ) : $secret_key = !empty( $encrypted_secret_key ) ? $this->tiny_2fa_decrypt_secret_key( $encrypted_secret_key ) : false; ?>
				<tr>
					<th><label for="tiny_2fa_email_enabled"><?php esc_html_e( 'Backup Codes', 'tiny-2fa' ); ?></label></th>
					<td><label><input type="checkbox" name="tiny_2fa_email_enabled" id="tiny_2fa_email_enabled" value="1" <?php checked( $two_factor_email_enabled, '1' ); ?>>
					<?php esc_html_e( 'Receive backup codes by email. You should disable this once you confirm you can log in with your authenticator app.', 'tiny-2fa' ); ?></label></td>
				</tr>
				<tr>
					<th><label><?php esc_html_e( 'Secret Key', 'tiny-2fa' ); ?></label></th>
					<td>
						<?php if ( $secret_key !== false ) : ?>
							<img src="<?php echo esc_attr( $this->tiny_2fa_generate_qr_code( $secret_key, $user->user_login ) ); ?>" alt="<?php esc_attr_e( 'Scan with Authenticator App', 'tiny-2fa' ); ?>" style="max-width:200px;height:auto"><br>
							<input type="text" id="tiny-2fa-secret-key" class="regular-text" value="<?php echo esc_attr( $secret_key ); ?>" readonly>
							<a href="#2fa" onclick="if(confirm('<?php echo esc_js( __( 'Are you sure? You will need to reconfigure your authenticator app.', 'tiny-2fa' ) ); ?>')){location.href=location.pathname+'?tiny-2fa-reg=1&_wpnonce=<?php echo esc_js( wp_create_nonce( 'tiny_2fa_regenerate_' . $user->ID ) ); ?>#2fa';}return false;" title="<?php esc_attr_e( 'Regenerate', 'tiny-2fa' ); ?>" style="text-decoration:none;vertical-align:middle">↻</a>
							<input type="hidden" name="tiny_2fa_regenerate" id="tiny_2fa_regenerate" value="0"><br>
							<?php esc_html_e( 'Scan QR code or manually enter the secret key into your authenticator app.', 'tiny-2fa' ); ?>
						<?php else : ?>
							<p style="color:#d63638">
								<?php esc_html_e( 'Error: Unable to decrypt secret key.', 'tiny-2fa' ); ?>
								<a href="#2fa" onclick="if(confirm('<?php echo esc_js( __( 'Are you sure? You will need to reconfigure your authenticator app.', 'tiny-2fa' ) ); ?>')){location.href=location.pathname+'?tiny-2fa-reg=1&_wpnonce=<?php echo esc_js( wp_create_nonce( 'tiny_2fa_regenerate_' . $user->ID ) ); ?>#2fa';}return false;"><?php esc_html_e( 'Regenerate Key', 'tiny-2fa' ); ?></a>
							</p>
							<input type="hidden" name="tiny_2fa_regenerate" id="tiny_2fa_regenerate_error" value="0">
						<?php endif; ?>
					</td>
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
		$two_factor_enabled = isset( $_POST['tiny_2fa_enabled'] ) ? '1' : '0';
		$two_factor_email_enabled = isset( $_POST['tiny_2fa_email_enabled'] ) ? '1' : '0';
		update_user_meta( $user_id, 'tiny_2fa_enabled', $two_factor_enabled );
		update_user_meta( $user_id, 'tiny_2fa_email_enabled', $two_factor_email_enabled );
		if ( $two_factor_enabled ) {
			$encrypted_secret_key = get_user_meta( $user_id, 'tiny_2fa_secret_key', true );
			if ( empty( $encrypted_secret_key ) ) {
				$secret_key = $this->tiny_2fa_generate_secret_key();
				$encrypted_secret_key = $this->tiny_2fa_encrypt_secret_key( $secret_key );
				update_user_meta( $user_id, 'tiny_2fa_secret_key', $encrypted_secret_key );
				update_user_meta( $user_id, 'tiny_2fa_email_enabled', '1' );
				add_filter( 'wp_redirect', function( $location ) {
					return $location . '#2fa';
				} );
			}
		}
	}

	public function tiny_2fa_handle_regenerate() {
		if ( !isset( $_GET['tiny-2fa-reg'] ) || $_GET['tiny-2fa-reg'] !== '1' ) {
			return;
		}
		if ( !is_admin() ) {
			return;
		}
		$user_id = get_current_user_id();
		if ( isset( $_GET['user_id'] ) ) {
			$user_id = absint( $_GET['user_id'] );
		}
		if ( !current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		if ( !isset( $_GET['_wpnonce'] ) || !wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'tiny_2fa_regenerate_' . $user_id ) ) {
			wp_die( esc_html__( 'Security check failed.', 'tiny-2fa' ) );
		}
		$two_factor_enabled = get_user_meta( $user_id, 'tiny_2fa_enabled', true );
		if ( $two_factor_enabled ) {
			$secret_key = $this->tiny_2fa_generate_secret_key();
			$encrypted_secret_key = $this->tiny_2fa_encrypt_secret_key( $secret_key );
			update_user_meta( $user_id, 'tiny_2fa_secret_key', $encrypted_secret_key );
		}
	}

	// ========================================
	// LOGIN & AUTHENTICATION
	// ========================================

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
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login form nonce verification is handled by WordPress core.
		if ( !isset( $_POST['user_2fa'] ) ) {
			return new WP_Error( 'two_factor_required', __( 'Two-factor authentication code is required.', 'tiny-2fa' ) );
		}
		$submitted_code = sanitize_text_field( wp_unslash( $_POST['user_2fa'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login form nonce verification is handled by WordPress core.
		$encrypted_secret_key = get_user_meta( $user->ID, 'tiny_2fa_secret_key', true );
		$secret_key = $this->tiny_2fa_decrypt_secret_key( $encrypted_secret_key );
		if ( $secret_key === false ) {
			return new WP_Error( 'two_factor_error', __( 'Two-factor authentication error. Please contact the site administrator.', 'tiny-2fa' ) );
		}
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

	// ========================================
	// BRUTE FORCE PROTECTION
	// ========================================

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
}

new Tiny_2FA();