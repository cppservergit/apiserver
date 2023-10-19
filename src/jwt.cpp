#include "jwt.h"

namespace 
{
	constexpr const char* LOGGER_SRC {"jwt"};
	
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

	std::string sign(std::string_view message, std::string_view secret) 
	{
		std::vector<unsigned char> msg {message.begin(), message.end()};
		std::vector<unsigned char> signature_bytes(EVP_MAX_MD_SIZE);
		unsigned int signature_length {0};
		HMAC(EVP_sha256(), secret.data(), secret.size(), msg.data(), msg.size(), signature_bytes.data(), &signature_length);
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
			} else
				logger::log(LOGGER_SRC, "warning", "invalid token format - cannot find second '.'");
		} else
			logger::log(LOGGER_SRC, "warning", "invalid token format - cannot find first '.'");
		return jt;
	}
	
	jwt::user_info parse_payload(const std::string& payload)
	{
		auto fields {json::parse(payload)};
		return jwt::user_info {
				fields["login"], 
				fields["mail"], 
				fields["roles"], 
				std::stol(fields["exp"])
			};
	}
}

namespace jwt
{
	std::string get_token(std::string_view username, std::string_view mail, std::string_view roles) noexcept
	{
		static jwt_config config;
		const time_t now {std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) + config.duration}; 
		const std::string json_header {R"({"alg":"HS256","typ":"JWT"})"};
		const std::string json_payload {std::format(R"({{"login":"{}","mail":"{}","roles":"{}","exp":{}}})", username, mail, roles, now)};
		std::string buffer {base64_encode(json_header) + "." + base64_encode(json_payload)};
		auto signature {sign(buffer, config.secret)};
		return buffer.append(".").append(signature);
	}
	
	std::pair<bool, user_info> is_valid(const std::string& token)	
	{
		static jwt_config config;
		auto jt {parse(token)};
		if (const std::string test{jt.header_encoded + "." + jt.payload_encoded}; jt.signature != sign(test, config.secret)) {
			logger::log(LOGGER_SRC, "warning", "invalid signature");
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
