gauth-pike
==========

Google Authenticator implementation in Pike. Currently only supports time-based codes.

Functions
---------

* gauth_totp_url: Returns a `otpauth`-URL (great for passing on to a QR-code generator).
* gauth_totp_code: Returns a code based on a key.

Example
-------

Example code is included which can be used to generate URLs and codes from the CLI. Run the script with `--help` for more information.

### Generate a otpauth-URL with a custom key

    $ pike gauth.pike -u -k AABBCCDDAABBCCDDAABB
    otpauth://totp/My%20service:My%20account?secret=VK54ZXNKXPGN3KV3&issuer=My%20service

### Generate a time-based (TOTP) code with a custom key

    $ pike gauth.pike -k AABBCCDDAABBCCDDAABB
    148058

