#include "env.h"

namespace 
{
	constexpr const char* LOGGER_SRC {"env"};
	
	struct env_vars 
	{
			unsigned short int read_env(const char* name, unsigned short int default_value) const noexcept;
			unsigned short int port{read_env("CPP_PORT", 8080)};
			unsigned short int http_log{read_env("CPP_HTTP_LOG", 0)};
			unsigned short int login_log{read_env("CPP_LOGIN_LOG", 0)};
			unsigned short int pool_size{read_env("CPP_POOL_SIZE", 4)};
			unsigned short int jwt_expiration{read_env("CPP_JWT_EXP", 600)};
	};	

	const env_vars ev;
	
	unsigned short int env_vars::read_env(const char* name, unsigned short int default_value) const noexcept
	{
		unsigned short int value{default_value};
		if (const char* env_p = std::getenv(name)) {
			std::string_view str(env_p);
			auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
			if (ec == std::errc::invalid_argument)
				logger::log(LOGGER_SRC, "warn", std::format("read_env() -> invalid argument for std::from_chars: {} env-var: {}", env_p, name));
			else if (ec == std::errc::result_out_of_range)
				logger::log(LOGGER_SRC, "warn", std::format("read_env() -> number out of range in std::from_chars: {} env-var: {}", env_p, name));
		}
		return value;
	}
}

namespace env
{
	std::string get_str(const std::string& name) noexcept
	{
		if (const char* env_p = std::getenv(name.c_str()))
			return std::string(env_p);
		else 
			return "";
		
	}

	unsigned short int port() noexcept 
	{ return ev.port; }

	unsigned short int http_log_enabled() noexcept 
	{ return ev.http_log; }

	unsigned short int pool_size() noexcept 
	{ return ev.pool_size; }

	unsigned short int login_log_enabled() noexcept 
	{ return ev.login_log; }

	unsigned short int jwt_expiration() noexcept 
	{ return ev.jwt_expiration; }

}
