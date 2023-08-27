#include "jwt.h"

namespace 
{
	const std::string LOGGER_SRC {"jwt"};
	
	struct jwt_config {
		std::string secret;
		unsigned short int duration;
		jwt_config() {
			duration = env::jwt_expiration();
			secret = env::get_str("CPP_JWT_SECRET");
			if (secret.empty())
				logger::log(LOGGER_SRC, "error", "environment variable CPP_JWT_SECRET not defined");
		}
	};
	
	struct user_info 
	{
		void clear() noexcept 
		{
			login = "";
			mail = "";
			roles = "";
			exp = 0;
		}
		std::string login{""};
		std::string mail{""};
		std::string roles{""};
		time_t exp{0};
	} thread_local t_user_info;		

	struct json_token
	{
		std::string header;
		std::string header_encoded;
		std::string payload;
		std::string payload_encoded;
		std::string signature;
	};	
	
	//all base64 code taken from https://gist.github.com/darelf/0f96e1d313e1d0da5051e1a6eff8d329
	constexpr char base64_url_alphabet[] = 
	{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
		'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
	};

	//custom overload to be used by sign()
	std::string base64_encode(const std::vector<unsigned char> & in, size_t len) 
	{
	  std::string out;
	  int val =0, valb=-6;
	  unsigned int i = 0;
	  for (i = 0; i < len; i++) {
		unsigned char c = in[i];
		val = (val<<8) + c;
		valb += 8;
		while (valb >= 0) {
		  out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
		  valb -= 6;
		}
	  }
	  if (valb > -6) {
		out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
	  }
	  return out;
	}

	std::string base64_encode(const std::string & in) 
	{
	  std::string out;
	  int val =0, valb=-6;
	  size_t len = in.length();
	  unsigned int i = 0;
	  for (i = 0; i < len; i++) {
		unsigned char c = in[i];
		val = (val<<8) + c;
		valb += 8;
		while (valb >= 0) {
		  out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
		  valb -= 6;
		}
	  }
	  if (valb > -6) {
		out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
	  }
	  return out;
	}

	std::string base64_decode(std::string_view in) 
	{
	  std::string out;
	  std::vector<int> T(256, -1);
	  unsigned int i;
	  for (i =0; i < 64; i++) T[base64_url_alphabet[i]] = i;

	  int val = 0, valb = -8;
	  for (i = 0; i < in.length(); i++) {
		unsigned char c = in[i];
		if (T[c] == -1) break;
		val = (val<<6) + T[c];
		valb += 6;
		if (valb >= 0) {
		  out.push_back(char((val>>valb)&0xFF));
		  valb -= 8;
		}
	  }
	  return out;
	}

	std::string sign(const std::string& message, const std::string& secret) 
	{
		std::vector<unsigned char> msg {message.begin(), message.end()};
		std::vector<unsigned char> signature_bytes(EVP_MAX_MD_SIZE);
		unsigned int signature_length {0};
		HMAC(EVP_sha256(), secret.c_str(), secret.size(), msg.data(), msg.size(), signature_bytes.data(), &signature_length);
		return base64_encode(signature_bytes, signature_length);
	}
	
	json_token parse(const std::string& token)
	{
		json_token jt;
		size_t pos {0};
		if (auto pos1 = token.find(".", pos); pos1 != std::string::npos) {
            jt.header_encoded = token.substr(pos,  pos1);
			pos = pos1 + 1;
			if (auto pos2 = token.find(".", pos + 1); pos2 != std::string::npos) {
				jt.payload_encoded = token.substr(pos,  pos2 - pos);
				pos = pos2 + 1;
				jt.signature = token.substr(pos);
                jt.header = base64_decode(jt.header_encoded);
                jt.payload = base64_decode(jt.payload_encoded);
			} 
		}
		return jt;
	}
	
	std::pair<int, std::string_view> get_attribute(std::string_view s, const std::string& name, size_t pos, bool is_numeric = false)
	{
		auto key {"\"" + name + "\":"};
		std::string_view value;
		pos = s.find(key, pos);
		if (pos != std::string::npos) {
			pos += key.size();
            if (!is_numeric) {
                auto pos1 {s.find("\"", pos)};
                if (pos1 != std::string::npos) {
                    auto pos2 {s.find("\"", pos1 + 1)};
                    value = s.substr(pos1 + 1, pos2 - pos1 - 1);
                    pos = pos2 + 1;
                }
            } else {
                auto pos1 {pos};
                auto pos2 {s.find("}", pos1)};
                if (pos2 != std::string::npos) {
                    value = s.substr(pos1, pos2 - pos1);
                }
            }
		}
		return make_pair(pos, value);
	}
	
	void parse_payload(const std::string& payload)
	{
		auto login {get_attribute(payload, "login", 0)};
		auto mail {get_attribute(payload, "mail", login.first)};
		auto roles {get_attribute(payload, "roles", mail.first)};
		auto exp {get_attribute(payload, "exp", roles.first, true)};
		t_user_info.login = login.second;
		t_user_info.mail = mail.second;
		t_user_info.roles = roles.second;
		t_user_info.exp = std::stol(std::string(exp.second));
	}
	
}

namespace jwt
{
	void clear() noexcept { t_user_info.clear(); }
	
	std::string get_token(const std::string& userlogin, const std::string& mail, const std::string& roles) noexcept
	{
		static jwt_config config;
		time_t now; time(&now); now += config.duration;
		std::string json_header {R"({"alg":"HS256","typ":"JWT"})"};
		std::string json_payload {"{\"login\":\"" + userlogin + "\",\"mail\":\"" + mail + "\",\"roles\":\"" + roles + "\",\"exp\":" + std::to_string(now) + "}"};
		std::string buffer {base64_encode(json_header) + "." + base64_encode(json_payload)};
		auto signature {sign(buffer, config.secret)};
		return buffer.append(".").append(signature);
	}
	
	bool is_valid(const std::string& token)	
	{
		static jwt_config config;
		t_user_info.clear();
		auto jt {parse(token)};
		const std::string test{jt.header_encoded + "." + jt.payload_encoded};
		if (jt.signature != sign(test, config.secret))
			return false;
		parse_payload(jt.payload);
		time_t now; time(&now);
		if (now < t_user_info.exp)
			return true;
		else
			return false;
	}

	std::string user_get_login() noexcept
	{
		return t_user_info.login;
	}

	std::string user_get_mail() noexcept
	{
		return t_user_info.mail;
	}

	std::string user_get_roles() noexcept
	{
		return t_user_info.roles;
	}

}
