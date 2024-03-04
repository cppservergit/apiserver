#include "login.h"

namespace 
{
	constexpr const char* LOGGER_SRC {"login"};
}

namespace login
{
	login_result::login_result(bool _result, 
		const std::string& _name, 
		const std::string& _mail, 
		const std::string& _roles, 
		const std::string& _error_code,
		const std::string& _error_description
		) noexcept
				: result{_result}, display_name{_name}, email{_mail}, roles{_roles}, error_code{_error_code}, error_description{_error_description}
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
	
	std::string login_result::get_error_code() const noexcept {
		return error_code;
	}

	std::string login_result::get_error_description() const noexcept {
		return error_description;
	}
	
	//login and password must be pre-processed for sql-injection protection
	//expects a resultset with these columns: mail, displayname, rolenames
	login_result bind(const std::string& login, const std::string& password)
	{
		std::string sql {std::format("select * from cpp_dblogin('{}', '{}')", login, password)};
		auto rec {sql::get_record("CPP_LOGINDB", sql)};
		if (rec["status"] == "OK") {
			return login_result {true, rec["displayname"], rec["email"], rec["rolenames"], "", ""};
		} else
			return login_result{false, "", "", "", rec["error_code"], rec["error_description"]};
	}
}
