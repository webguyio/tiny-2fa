=== Tiny 2FA + Brute Force Protection ===

Contributors: webguyio
Donate link: https://webguy.io/donate
Tags: 2fa, mfa, security, login
Requires at least: 5.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 0.2
License: CC0
License URI: https://creativecommons.org/public-domain/cc0/

A simple two-factor authentication plugin that just works.

== Description ==

This is probably the 2FA plugin you're looking for.

Secure, private, and *lightweight*.

Integrates into WordPress like a native feature.

= Proactive vs Reactive Security =

Prevents attacks instead of reacting to them. The best breach is the one that never happens.

= How it Works =

1. Install and activate the plugin
2. Go to *Users > Profile > Two-Factor Authentication* (near the bottom)
3. Check the box next to "Enable 2FA" and click "Update Profile"
4. 2FA and Backup Codes are now enabled
5. Scan the QR code or manually enter the secret key into your auth app of choice (and be sure to rename the generic site name "2FA" to something more useful)
6. Once successful login with a 2FA code from your app has been confirmed, you should disable Backup Codes
7. Brute force protection is enabled by default and can be managed site-wide by admins in profile settings

Backup Codes have been rethought from the usual method you might be used to. Read more about that in the FAQ below.

= Need Support? =

Ask for help [here](https://github.com/webguyio/tiny-2fa/issues).

== Installation ==

**Automatic**

* From your WordPress Admin, navigate to: *Plugins > Add New*
* Search for: "Tiny 2FA"
* Install it
* Activate it

**Manual**

* Download
* Unzip
* Upload to /plugins/ folder
* Activate

== Frequently Asked Questions ==

= I locked myself out of my admin! =

Try not to panic; you're not permanently locked out and nothing has been lost. You'll simply need to disable the Tiny 2FA plugin to regain access.

The simplest way to do that is to access your */wp-content/plugins* folder via FTP and rename the */tiny-2fa* folder to anything else. Once you're back in your admin, you can restore the folder name and proceed to adjust your 2FA settings.

= I'm positive I entered my username, password, and 2FA code correctly, but I still can't log in! =

There are a few quirks to check for that could disrupt the general 2FA process, which aren't exclusive to Tiny 2FA:

1. The code you're trying to enter may have expired. Even if you get a fresh code, you may need to reload the login page again first before trying the new code.
2. You may need to clear the browser cache and try again.
3. If you're using Cloudflare, you'll need to either [restore visitor IPs](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/) or disable brute force protection.
4. If you're using a caching plugin, make sure it doesn't cache login pages or otherwise exclude your login page in its settings.
5. In your authenticator app, you may need to find and use a setting called something like "Sync Clock with Google."

= What 2FA methods are available? =

Only TOTP at this time. This is the most common 2FA method, the one you're probably most familiar with already. It's more secure than 2FA via SMS or email, but not as secure as a hardware key (overkill for most people), which is probably the only other option I'd consider adding.

= What apps are compatible? =

There are many mobile, desktop, and browser apps that support TOTP, including: Google Authenticator, Microsoft Authenticator, Proton Authenticator, Ente Auth, Authy, Bitwarden, LastPass, and 1Password.

= How do I generate a new secret key? =

Simply disable and re-enable 2FA in your profile settings to get a new key.

= How's the security? =

Other than storing secret keys in an encrypted format (apparently most sites just save them in plaintext), it's a pretty standard implementation (but having any 2FA in place is infinitely more secure than no 2FA at all).

= How's the privacy? =

As it turns out, generating QR codes is not a trivial matter. I explored generating them locally, but it added a lot of bloat to the plugin. So, I've opted to use an external service instead.

I'm using [QuickChart](https://quickchart.io/privacy/) (rather than Google, a popular choice) to generate QR codes, and for extra privacy, proxying the requests through [Cloudflare](https://www.cloudflare.com/privacypolicy/).

QuickChart will only ever know the secret key, but not the site name, username, or IP address it belongs to. Cloudflare will know the server IP the request is coming from, but still not the name of the website or user.

= How do Backup Codes work differently with your plugin? =

The way I've envisioned Backup Codes is simple: immediately upon enabling 2FA, Backup Codes will be on by default. This means that you'll receive codes by email until you're certain you've set up an authentication app correctly, and then you should disable them.

= Why do Backup Codes work differently with your plugin? =

I don't like the current implementation of the common Backup Codes feature that comes with most 2FAs. I think it creates a burden for the user to back them up, which if they're capable of doing, they're also capable of backing up their secret key in the first place without adding an unnecessary chore and new vulnerability while they're at it.

I think I've been able to improve upon the concept of Backup Codes, at least in the WordPress environment where most users are going to be the admin of their own website anyway. The entire point of Backup Codes in the first place is to offer a second chance to avoid being locked out of your account in case you lost your secret key. But for most WordPress websites, and probably many websites in general these days, the added vulnerability doesn't seem to match the intended usefulness.

I'm open to being wrong about this. If you feel my thinking is flawed or you have any other suggestion for improving the security of Tiny 2FA, please let me know.

== Changelog ==

= 0.2 =
* Added brute force protection

= 0.1 =
* New