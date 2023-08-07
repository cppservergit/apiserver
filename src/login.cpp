#include "login.h"

namespace 
{
	const std::string LOGGER_SRC {"login"};
	constexpr int MAX_RETRIES{3};
	
	//get a clean error message suitable for JSON logs
	inline std::string get_error(PGconn* conn)
	{
		std::string msg {PQerrorMessage(conn)};
		if (auto pos = msg.find("\n"); pos != std::string::npos)
			msg.erase(pos);
		if (auto pos = msg.find("ERROR:  "); pos != std::string::npos)
			msg.erase(0, pos + 8);
		for (char& c: msg) 
			if (c == '"') c = '\'';
		return msg;
	}	
	
	struct dbutil 
	{
		PGconn* conn;
		std::string m_dbconnstr;
		
		dbutil()
		{
			m_dbconnstr = env::get_str("CPP_LOGINDB");
			conn = PQconnectdb(m_dbconnstr.c_str());
			if (PQstatus(conn) != CONNECTION_OK)
				logger::log(LOGGER_SRC, "error", "login::dbutil() -> " + get_error(conn), true);
		}
		
		~dbutil() {
			if (conn) {
				PQfinish(conn);
			}
		}

		inline void reset_connection() noexcept
		{
			if ( PQstatus(conn) == CONNECTION_BAD ) {
				logger::log(LOGGER_SRC, "warn", "login::dbutil::reset_connection() -> connection to database " + std::string(PQdb(conn)) + " no longer valid, reconnecting... ", true);
				PQfinish(conn);
				conn = PQconnectdb(m_dbconnstr.c_str());
				if (PQstatus(conn) != CONNECTION_OK)
					logger::log(LOGGER_SRC, "error", 
						"login::dbutil::reset_connection() -> error reconnecting to database " + std::string(PQdb(conn)) + " - " + get_error(conn), true);
				else {
					logger::log(LOGGER_SRC, "info", 
						"login::dbutil::reset_connection() -> connection to database " +  std::string(PQdb(conn)) + " restored", true);
				}
			}
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
	bool bind(const std::string& login, const std::string& password)
	{
		constexpr int EXPECTED_COLS{3};
		int retries {0};
		bool flag{false};
		m_user.email.clear(); 
		m_user.display_name.clear();
		m_user.roles.clear();
		std::string sql {"select * from cpp_dblogin('" + login + "', '" + password + "')"};

	  retry:
		PGresult *res = PQexec(db.conn, sql.c_str());
		if (PQresultStatus(res) != PGRES_TUPLES_OK) {
			PQclear(res);
			if ( PQstatus(db.conn) == CONNECTION_BAD ) {
				if (retries == MAX_RETRIES) {
					std::string error_message{"login::bind() -> cannot connect to database"};
					throw std::runtime_error(error_message);
				} else {
					retries++;
					db.reset_connection();
					goto retry;
				}
			} else {
				throw std::runtime_error("login::bind() -> " + get_error(db.conn));
			}
		}

		if(PQnfields(res) != EXPECTED_COLS) {
			PQclear(res);
			std::string error_message{"login::bind() -> the SQL function CPP_DBLOGIN returned an invalid number of columns, expected: " + std::to_string(EXPECTED_COLS)};
			throw std::runtime_error(error_message);			
		}

		if ( PQntuples(res) > 0) {
			m_user.email.append( PQgetvalue(res, 0, 0) );
			m_user.display_name.append( PQgetvalue(res, 0, 1 ) );
			m_user.roles.append( PQgetvalue(res, 0, 2 ) );
			flag = true;
		}
		PQclear(res);
		return flag;
	}
}