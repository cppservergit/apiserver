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
		std::string m_dbconnstr;
		PGconn* conn{nullptr};
				
		dbutil() = default; 
		
		explicit dbutil(const std::string& conn_info) noexcept: m_dbconnstr{conn_info}
		{
			conn = PQconnectdb(m_dbconnstr.c_str());
			if (PQstatus(conn) != CONNECTION_OK)
				logger::log(LOGGER_SRC, "error", "dbutil() -> $1", {get_error(conn)}, true);
		}
		
		dbutil(dbutil &&source) noexcept: m_dbconnstr{source.m_dbconnstr}, conn{source.conn}
		{
			source.conn = nullptr;
		}

		dbutil(const dbutil &source) noexcept: m_dbconnstr{source.m_dbconnstr}, conn{source.conn}
		{
		}
		
		~dbutil() {
			if (conn) 
				PQfinish(conn);
		}
		
		inline void reset_connection() noexcept
		{
			if ( PQstatus(conn) == CONNECTION_BAD ) {
				logger::log(LOGGER_SRC, "warn", "reset_connection() -> connection to database $1 no longer valid, reconnecting... ", {std::string(PQdb(conn))}, true);
				PQfinish(conn);
				conn = PQconnectdb(m_dbconnstr.c_str());
				if (PQstatus(conn) != CONNECTION_OK)
					logger::log(LOGGER_SRC, "error", "reset_connection() -> error reconnecting to database $1: $2", {std::string(PQdb(conn)), get_error(conn)}, true);
				else
					logger::log(LOGGER_SRC, "info", "reset_connection() -> connection to database $1 restored", {std::string(PQdb(conn))}, true);
			}
		}
	};

	//taken from https://www.cppstories.com/2021/heterogeneous-access-cpp20/ 
	//addresses issues raised by rule cpp:S6045 from SonarCloud static analyzer
	struct string_hash {
	  using is_transparent = void;
	  [[nodiscard]] size_t operator()(const char *txt) const {
		return std::hash<std::string_view>{}(txt);
	  }
	  [[nodiscard]] size_t operator()(std::string_view txt) const {
		return std::hash<std::string_view>{}(txt);
	  }
	  [[nodiscard]] size_t operator()(const std::string &txt) const {
		return std::hash<std::string>{}(txt);
	  }
	};

	//thread_local  std::unordered_map<std::string, dbutil> dbconns;

	PGconn* getdb(const std::string& dbname, bool reset = false)
	{
		thread_local  std::unordered_map<std::string, dbutil, string_hash, std::equal_to<>> dbconns;
		if (!dbconns.contains(dbname)) {
			std::string connstr{env::get_str(dbname)};
			if (!connstr.empty()) {
				auto [iter, success] = dbconns.try_emplace(dbname, connstr);
				return iter->second.conn;
			}
			else {
				std::string error{logger::format("getdb() -> invalid dbname: $1", {dbname})};
				throw std::runtime_error(error);
			}
		} else {
			if (reset)
				dbconns[dbname].reset_connection();
			return dbconns[dbname].conn;
		}
	}

	void retry(const std::string& dbname, PGconn* conn, int& retries, const std::string& sql)
	{
		if ( PQstatus(conn) == CONNECTION_BAD ) {
			if (retries == max_retries) {
				std::string error{logger::format("retry() -> cannot connect to database:: $1", {dbname})};
				throw std::runtime_error(error);
			} else {
				retries++;
				getdb(dbname, true);
			}
		} else {
			std::string error {logger::format("db_exec() $1 -> sql: $2", {get_error(conn), sql})};
			throw std::runtime_error(error);
		}		
	}

	template<typename T, class FN>
	T db_exec(const std::string& dbname, const std::string& sql, FN func) {
		int retries {0};
		while (true) {
			PGconn* conn = getdb(dbname);
			PGresult* res = PQexec(conn, sql.c_str());
			auto status {PQresultStatus(res)};
			if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
				PQclear(res);
				retry(dbname, conn, retries, sql);
			} else {
				return func(res);
			}
		}
	}
}

namespace sql 
{
	//executes a query that doesn't return rows (data modification query)
	void exec_sql(const std::string& dbname, const std::string& sql)
	{
		return db_exec<void>(dbname, sql, [](PGresult *res) {
			PQclear(res);
			return;
		});
	}
	
	//returns true if the query retuned 1+ row
	bool has_rows(const std::string& dbname, const std::string &sql)
	{
		return db_exec<bool>(dbname, sql, [](PGresult *res){
				bool result {true};
				if (PQntuples(res) == 0)
					result = false;
				PQclear(res);
				return result;
		});
	}	
	
	//returns only the first rows of a resultset, use of "limit 1" or "where col=pk" in the query is recommended
	std::unordered_map<std::string, std::string> get_record(const std::string& dbname, const std::string& sql)
	{
		return db_exec<std::unordered_map<std::string, std::string>>(dbname, sql, [](PGresult *res){
				std::unordered_map<std::string, std::string> rec;
				int rows {PQntuples(res)};
				int cols {PQnfields(res)};
				if (rows) {
					for(int j=0; j < cols; j++) {
						rec.emplace(PQfname(res, j), PQgetvalue(res, 0, j));
					}
				}
				PQclear(res);
				return rec;
		});
	}

	//executes SQL that returns a single row with a single column containing a JSON response when data is available
	//throws exception in case of database error
	//returns JSON response with status OK or EMPTY (if query finds no rows)
	std::string get_json_response(const std::string& dbname, const std::string &sql)
	{
		return db_exec<std::string>(dbname, sql, [](PGresult *res){
				std::string json;
				int rows {PQntuples(res)};
				bool is_null {false};
				if (rows) {
					is_null = PQgetisnull(res, 0, 0);
					if (!is_null) 
						json.append("{\"status\":\"OK\", \"data\":").append(PQgetvalue(res, 0, 0)).append("}");
				}
				if (!rows || is_null)
					json.append(R"({"status":"EMPTY"})");
				PQclear(res);
				return json;
		});
	}
}
