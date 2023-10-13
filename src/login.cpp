#include "login.h"

namespace 
{
	constexpr const char* LOGGER_SRC {"login"};
}

namespace login
{
	login_result::login_result(bool _result, const std::string& _name, const std::string& _mail,const std::string& _roles) noexcept
				: result{_result}, display_name{_name}, email{_mail}, roles{_roles}
	{ }
			
	bool login_result::ok() const noexcept {
		return result;
	}
	
	std::string login_result::get_email() const noexcept {
		return email;
	}

	std::string login_result::get_display_name() const noexcept {
		return display_name;
	}

	std::string login_result::get_roles() const noexcept {
		return roles;
	}
	
	//login and password must be pre-processed for sql-injection protection
	//expects a resultset with these columns: mail, displayname, rolenames
	login_result bind(const std::string& login, const std::string& password)
	{
		std::string sql {std::format("execute cpp_dblogin '{}', '{}'", login, password)};
		if (auto rec {sql::get_record("CPP_LOGINDB", sql)}; !rec.empty()) {
			return login_result {true, rec["displayname"], rec["email"], rec["rolenames"]};
		} else
			return login_result{false, "", "", ""};
	}
}
