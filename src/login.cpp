#include "login.h"

namespace 
{
	const std::string LOGGER_SRC {"login"};
	
	struct dbutil 
	{
		std::string m_dbconnstr;
		dbutil()
		{
			m_dbconnstr = env::get_str("CPP_LOGINDB");
			sql::connect("LOGINDB", m_dbconnstr);
		}
	};
	thread_local dbutil db;

	struct user_info
	{
		std::string email{""};
		std::string display_name{""};
		std::string roles{""};
		user_info() { email.reserve(50); display_name.reserve(50); roles.reserve(255);}
	};
	thread_local user_info m_user;
}

namespace login
{
	std::string get_email() noexcept {
		return m_user.email;
	}

	std::string get_display_name() noexcept {
		return m_user.display_name;
	}

	std::string get_roles() noexcept {
		return m_user.roles;
	}
		
	//login and password must be pre-processed for sql-injection protection
	//expects a resultset with these columns: mail, displayname, rolenames
	bool bind(const std::string& login, const std::string& password)
	{
		bool flag{false};
		m_user.email.clear(); 
		m_user.display_name.clear();
		m_user.roles.clear();
		std::string sql {"select * from cpp_dblogin('" + login + "', '" + password + "')"};
		
		auto rec {sql::get_record("LOGINDB", sql)};
		if ( rec.size() ) {
			m_user.email = rec["mail"];
			m_user.display_name = rec["displayname"];
			m_user.roles = rec["rolenames"];
			flag = true;
		}
		return flag;
	}
}
