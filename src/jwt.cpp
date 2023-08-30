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

	//original code modified to use std::ranges as suggested by sonarcloud static analyzer
	//and generic code to support string_view and vector
	template<typename T>
	std::string base64_encode(const T& in) 
	{
	  std::string out;
	  out.reserve(127);
	  int val = 0;
	  int valb = -6;
	  std::ranges::for_each(in, [&](unsigned char c) {
		val = (val<<8) + c;
		valb += 8;
		while (valb >= 0) {
		  out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
		  valb -= 6;
		}
	  });
	  if (valb > -6) 
		out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
	  return out;
	}

    //original code modified to use std::ranges as suggested by sonarcloud static analyzer
	std::string base64_decode(std::string_view in) 
	{
	  std::string out;
	  out.reserve(127);
	  std::vector<int> T(256, -1);
	  for (unsigned int i = 0; i < 64; i++) 
		  T[base64_url_alphabet[i]] = i;
	  int val = 0; 
	  int valb = -8;
      std::ranges::for_each(in, [&](unsigned char c) {
		if (T[c] == -1) return;
		val = (val<<6) + T[c];
		valb += 6;
		if (valb >= 0) {
		  out.push_back(char((val>>valb)&0xFF));
		  valb -= 8;
		}
	  });
	  return out;
	}

	std::string sign(std::string_view message, const std::string& secret) 
	{
		std::vector<unsigned char> msg {message.begin(), message.end()};
		std::vector<unsigned char> signature_bytes(EVP_MAX_MD_SIZE);
		unsigned int signature_length {0};
		HMAC(EVP_sha256(), secret.c_str(), secret.size(), msg.data(), msg.size(), signature_bytes.data(), &signature_length);
		signature_bytes.erase(signature_bytes.begin() + signature_length, signature_bytes.end());
		return base64_encode(signature_bytes);
	}
	
	json_token parse(std::string_view token)
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
	
	jwt::user_info parse_payload(const std::string& payload)
	{
		auto [login_pos, login] {get_attribute(payload, "login", 0)};
		auto [mail_pos, mail] {get_attribute(payload, "mail", login_pos)};
		auto [roles_pos, roles] {get_attribute(payload, "roles", mail_pos)};
		auto [exp_pos, exp] {get_attribute(payload, "exp", roles_pos, true)};
		return jwt::user_info {std::string(login), std::string(mail), std::string(roles), std::stol(std::string(exp))};
	}
	
}

namespace jwt
{
	std::string get_token(const std::string& userlogin, const std::string& mail, const std::string& roles) noexcept
	{
		static jwt_config config;
		const time_t now {std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) + config.duration}; 
		const std::string json_header {R"({"alg":"HS256","typ":"JWT"})"};
		
		std::array<char, 512> buf;
		std::string fmt {R"({"login":"%s","mail":"%s","roles":"%s","exp":%d})"};
		std::snprintf(buf.data(), buf.size(), fmt.c_str(), userlogin.c_str(), mail.c_str(), roles.c_str(), now);
		const std::string json_payload {buf.data()};
		
		std::string buffer {base64_encode(json_header) + "." + base64_encode(json_payload)};
		auto signature {sign(buffer, config.secret)};
		return buffer.append(".").append(signature);
	}
	
	std::pair<bool, user_info> is_valid(const std::string& token)	
	{
		static jwt_config config;
		auto jt {parse(token)};
		if (const std::string test{jt.header_encoded + "." + jt.payload_encoded}; jt.signature != sign(test, config.secret)) {
			logger::log(LOGGER_SRC, "warning", "invalid signature", true);
			return std::make_pair(false, user_info());
		}
		auto user {parse_payload(jt.payload)};
		const time_t now {std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};
		if (now < user.exp)
			return std::make_pair(true, user);
		else 
			return std::make_pair(false, user_info());
		
	}
}
