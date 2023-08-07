#include "sql.h"

namespace 
{
	const std::string LOGGER_SRC {"sql"};
	constexpr int max_retries{3};
	constexpr int PG_DATE = 1082;
	constexpr int PG_TIMESTAMP = 1114;
	constexpr int PG_VARCHAR = 1043;
	constexpr int PG_TEXT = 25;	

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
		
		std::string m_dbconnstr{""};
		PGconn* conn{nullptr};
				
		dbutil() 
		{
		}
		
		dbutil(const std::string& conn_info): m_dbconnstr{conn_info}
		{
			conn = PQconnectdb(m_dbconnstr.c_str());
			if (PQstatus(conn) != CONNECTION_OK)
				logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + ": " + get_error(conn), true);
		}
		
		dbutil(dbutil &&source) : m_dbconnstr{source.m_dbconnstr}, conn{source.conn}
		{
			source.conn = nullptr;
		}

		dbutil(const dbutil &source) : m_dbconnstr{source.m_dbconnstr}, conn{source.conn}
		{
		}
		
		~dbutil() {
			if (conn) 
				PQfinish(conn);
		}
		
		inline void reset_connection() noexcept
		{
			if ( PQstatus(conn) == CONNECTION_BAD ) {
				logger::log(LOGGER_SRC, "warn", std::string(__FUNCTION__) + ": connection to database " + std::string(PQdb(conn)) + " no longer valid, reconnecting... ", true);
				PQfinish(conn);
				conn = PQconnectdb(m_dbconnstr.c_str());
				if (PQstatus(conn) != CONNECTION_OK)
					logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + ": error reconnecting to database " + std::string(PQdb(conn)) + " - " + get_error(conn), true);
				else
					logger::log(LOGGER_SRC, "info", std::string(__FUNCTION__) + ": connection to database " +  std::string(PQdb(conn)) + " restored", true);
			}
		}
	
	};

	thread_local  std::unordered_map<std::string, dbutil> dbconns;

	PGconn* getdb(const std::string& dbname)
	{
		if (!dbconns.contains(dbname)) {
			std::string error{std::string(__FUNCTION__) + ": invalid dbname: " + dbname};
			throw std::runtime_error(error.c_str());
		}
		return dbconns[dbname].conn;
	}

	void reset(const std::string& dbname) noexcept
	{
		dbconns[dbname].reset_connection();
	}

}

namespace sql 
{
	void connect(const std::string& dbname, const std::string& conn_info)
	{
		if (!dbconns.contains(dbname)) { 
			dbconns.insert({dbname, dbutil(conn_info)});
		}
		else {
			std::string error{std::string(__FUNCTION__) + ": duplicated dbname: " + dbname};
			throw std::runtime_error(error.c_str());
		}
	}

	//executes a query that doesn't return rows (data modification query)
	void exec_sql(const std::string& dbname, const std::string& sql)
	{
		int retries {0};
	retry:
		PGconn *conn = getdb(dbname);
		PGresult *res = PQexec(conn, sql.c_str());
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			PQclear(res);
			if ( PQstatus(conn) == CONNECTION_BAD ) {
				if (retries == max_retries) {
					std::string error_message{"cannot connect to database: " + dbname};
					throw std::runtime_error(error_message);
				} else {
					retries++;
					reset(dbname);
					goto retry;
				}
			} else {
				std::string error {get_error(conn) + " sql: " + sql};
				throw std::runtime_error(error);
			}
		}
		PQclear(res);
	}
	
	//returns true if the query retuned 1+ row
	bool has_rows(const std::string& dbname, const std::string &sql)
	{
		int retries {0};
	
	retry:
		PGconn *conn = getdb(dbname);
		PGresult *res = PQexec(conn, sql.c_str());
		
		if (PQresultStatus(res) != PGRES_TUPLES_OK) {
			PQclear(res);
			if ( PQstatus(conn) == CONNECTION_BAD ) {
				if (retries == max_retries) {
					std::string error_message{"cannot connect to database: " + dbname};
					throw std::runtime_error(error_message);
				} else {
					retries++;
					reset(dbname);
					goto retry;
				}
			} else {
				std::string error {get_error(conn) + " sql: " + sql};
				throw std::runtime_error(error);
			}
		}
		
		bool result {true};
		if (PQntuples(res) == 0)
			result = false;
		PQclear(res);
		return result;
	}	
	
	//returns only the first rows of a resultset, use of "limit 1" or "where col=pk" in the query is recommended
	std::unordered_map<std::string, std::string> get_record(const std::string& dbname, const std::string& sql)
	{
		int retries {0};
		std::unordered_map<std::string, std::string> rec;
		rec.reserve(5);
		
	retry:
		PGconn *conn = getdb(dbname);	
		PGresult *res = PQexec(conn, sql.c_str());
		
		if (PQresultStatus(res) != PGRES_TUPLES_OK) {
			PQclear(res);
			if ( PQstatus(conn) == CONNECTION_BAD ) {
				if (retries == max_retries) {
					std::string error_message{"cannot connect to database: " + dbname};
					throw std::runtime_error(error_message);
				} else {
					retries++;
					reset(dbname);
					goto retry;
				}
			} else {
				std::string error {get_error(conn) + " sql: " + sql};
				throw std::runtime_error(error);
			}
		}
		
		int rows {PQntuples(res)};
		int cols {PQnfields(res)};
		if (rows) {
			for(int j=0; j<cols; j++) {
				rec.emplace(PQfname(res, j), PQgetvalue(res, 0, j));
			}
		}
		PQclear(res);
		return rec;
	}

	//executes SQL that returns a single row with a single column containing a JSON response when data is available
	//throws exception in case of database error
	//returns JSON response with status OK or EMPTY (if query finds no rows)
	std::string get_json_response(const std::string& dbname, const std::string &sql)
	{
		int retries {0};
		
	retry:
		PGconn *conn = getdb(dbname);	
		PGresult *res = PQexec(conn, sql.c_str());
		
		if (PQresultStatus(res) != PGRES_TUPLES_OK) {
			PQclear(res);
			if ( PQstatus(conn) == CONNECTION_BAD ) {
				if (retries == max_retries) {
					std::string error_message{"cannot connect to database: " + dbname};
					throw std::runtime_error(error_message);
				} else {
					retries++;
					reset(dbname);
					goto retry;
				}
			} else {
				std::string error {get_error(conn) + " sql: " + sql};
				throw std::runtime_error(error);
			}
		}
	
		std::string json;
		int rows {PQntuples(res)};
		bool is_null {0};
		if (rows) {
			is_null = PQgetisnull(res, 0, 0);
			if (!is_null) 
				json.append("{\"status\":\"OK\", \"data\":").append(PQgetvalue(res, 0, 0)).append("}");
		}
		if (!rows || is_null)
			json.append("{\"status\":\"EMPTY\"}");
		PQclear(res);
		return json;
	}
	
}
