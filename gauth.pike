//! Google Authenticator implementation in Pike
//! ===========================================================================
//! Author:  Pontus "Frigolit" Rodling <frigolit@frigolit.net>
//! Website: https://github.com/Frigolit/gauth-pike
//! License: Public domain

//! Test code
int main(int argc, array argv) {
	int    f_help = Getopt.find_option(argv, "h", "help");
	int    f_url  = Getopt.find_option(argv, "u", "url");

	string s_acc  = Getopt.find_option(argv, "a", "account", UNDEFINED, "My account");
	string s_svc  = Getopt.find_option(argv, "s", "service", UNDEFINED, "My service");
	string s_iss  = Getopt.find_option(argv, "i", "issuer", UNDEFINED, "My issuer");
	string s_key  = Getopt.find_option(argv, "k", "key", UNDEFINED, "0123456789ABCDEF0123");

	if (f_help) {
		werror("-h|--help              Shows this help screen.\n");
		werror("-u|--url               Output a otpauth-URL, otherwise output the current code.\n");
		werror("\n");

		werror("-a|--account <name>    Specify account name (for --url, default: \"My account\").\n");
		werror("-s|--service <name>    Specify service name (for --url, default: \"My service\").\n");
		werror("-i|--issuer <name>     Specify issuer name (for --url, default: \"My issuer\").\n");
		werror("-k|--key <hex>         Specify key in hex (default: 0123456789ABCDEF0123).\n");
		return 0;
	}

	// Convert key from hex
	s_key = String.hex2string(s_key);

	if (f_url) {
		// URL
		write(gauth_totp_url(s_acc, s_svc, s_iss, s_key));
		return 0;
	}
	else {
		// Code
		write("%s\n", gauth_totp_code(s_key));
	}
}

//! Generate a TOTP URL
string gauth_totp_url(string accountname, string|void service, string|void issuer, string key) {
	if (sizeof(key) != 10) throw(({ "Invalid key length\n", backtrace() }));

	// Base32-encoder for 10-byte strings only
	string encode_key_base32(string key) {
		array chars = (array)"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

		string r = "";
		int a;

		sscanf(key, "%10c", a);

		for (int i = 0; i < 16; i++) {
			int n = (a >> (75 - i * 5)) & 0b11111;
			r += sprintf("%c", chars[n]);
		}

		return r;
	};

	// Build the URL
	string r = "otpauth://totp/";

	if (service && service != "") r += Protocols.HTTP.percent_encode(service) + "%3A";

	r += Protocols.HTTP.percent_encode(accountname) + "?secret=" + encode_key_base32(key);

	if (issuer && issuer != "") r += "&issuer=" + Protocols.HTTP.percent_encode(issuer);

	return r;
}

//! Generate a time-based (TOTP) code
string gauth_totp_code(string key) {
	if (sizeof(key) != 10) throw(({ "Invalid key length\n", backtrace() }));
	
	// http://en.wikipedia.org/wiki/Google_Authenticator#Pseudocode_for_Time_OTP

	string message = sprintf("%8c", time() / 30);
	string hash    = Crypto.HMAC(Crypto.SHA1)(key)(message);
	int    offset  = hash[-1] & 0b1111;
	string th      = hash[offset..offset + 3];

	int code = ((th[0] & 0x7F) << 24) | (th[1] << 16) | (th[2] << 8) | th[3];

	return sprintf("%06d", code % 1000000);
}

