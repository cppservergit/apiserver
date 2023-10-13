#include "sql.h"

namespace 
{
	constexpr const char* LOGGER_SRC {"sql"};
	constexpr int max_retries{3};
	constexpr int PG_DATE = 1082;
	constexpr int PG_TIMESTAMP = 1114;
	constexpr int PG_VARCHAR = 1043;
	constexpr int PG_TEXT = 25;	

	//get a clean error message suitable for JSON logs
	constexpr  std::string get_error(const PGconn* conn)
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

	void dbclose(PGconn* conn) {
		logger::log(LOGGER_SRC, "debug", std::format("closing database {:#010x}", reinterpret_cast<intptr_t>(conn)));
		if (conn) 
			PQfinish(conn);
	}

	struct dbutil 
	{
		std::string name;
		std::string dbconnstr;
		std::unique_ptr<PGconn, decltype(&dbclose)> conn;

		dbutil(): name{"null"}, conn{nullptr, &dbclose} {}
	
		explicit dbutil(std::string_view _name, std::string_view _connstr) noexcept: 
			name{_name}, 
			dbconnstr{_connstr}, 
			conn{PQconnectdb(dbconnstr.c_str()), &dbclose}
		{
			logger::log(LOGGER_SRC, "debug", std::format("connecting to {} {:#010x}", name, reinterpret_cast<intptr_t>(conn.get())));
			if (PQstatus(conn.get()) != CONNECTION_OK)
				logger::log(LOGGER_SRC, "error", std::format("cannot connect to database -> {}: {}", name, get_error(conn.get())));
		}

		constexpr void reset_connection() noexcept
		{
			if ( PQstatus(conn.get()) == CONNECTION_BAD ) {
				logger::log(LOGGER_SRC, "warn", std::format("reset_connection() -> connection to database {} no longer valid, reconnecting... ", PQdb(conn.get())));
				PQfinish(conn.get());
				conn.reset(PQconnectdb(dbconnstr.c_str()));
				if (PQstatus(conn.get()) != CONNECTION_OK)
					logger::log(LOGGER_SRC, "error", std::format("reset_connection() -> error reconnecting to database {}: {}", PQdb(conn.get()), get_error(conn.get())));
				else
					logger::log(LOGGER_SRC, "info", std::format("reset_connection() -> connection to database {} restored", PQdb(conn.get())));
			}
		}
	};

	struct dbconns {
		constexpr static int MAX_CONNS {5};
		std::array<dbutil, MAX_CONNS> conns;
		int index {0};

		constexpr std::pair<bool, PGconn*> get(std::string_view name, bool reset = false) noexcept
		{
			for (auto& db: conns) 
				if (db.name == name) {
					if (reset)
						db.reset_connection();
					return std::make_pair(true, db.conn.get());
				}
			return std::make_pair(false, nullptr);
		}

		constexpr PGconn* add(std::string_view name, std::string_view connstr)
		{
			if (index == MAX_CONNS)
				throw sql::database_exception(std::format("dbconns::add() -> no more than {} database connections allowed: {}", MAX_CONNS, name));
			conns[index] = dbutil(name, connstr);
			++index;
			return conns[index - 1].conn.get();
		}

	};

	constexpr PGconn* getdb(const std::string_view name, bool reset = false)
	{
	    thread_local dbconns dbc;
		if (auto [result, conn]{dbc.get(name, reset)}; result) {
			return conn;
		} else {
			auto connstr {env::get_str(name.data())};
			return dbc.add(name, connstr);
		}
	}

	constexpr void retry(const std::string& dbname, const PGconn* conn, int& retries, const std::string& sql)
	{
		if ( PQstatus(conn) == CONNECTION_BAD ) {
			if (retries == max_retries) {
				throw sql::database_exception(std::format("retry() -> cannot connect to database:: {}", dbname));
			} else {
				retries++;
				getdb(dbname, true);
			}
		} else {
			throw sql::database_exception(std::format("db_exec() {} -> sql: {}", get_error(conn), sql));
		}
	}

	template<typename T, class FN>
	constexpr T db_exec(const std::string& dbname, const std::string& sql, FN func) 
	{
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
	std::unordered_map<std::string, std::string, util::string_hash, std::equal_to<>> get_record(const std::string& dbname, const std::string& sql)
	{
		return db_exec<std::unordered_map<std::string, std::string, util::string_hash, std::equal_to<>>>(dbname, sql, [](PGresult *res){
				std::unordered_map<std::string, std::string, util::string_hash, std::equal_to<>> rec;
				int rows {PQntuples(res)};
				int cols {PQnfields(res)};
				if (rows) {
					for(int j=0; j < cols; j++) {
						rec.try_emplace(PQfname(res, j), PQgetvalue(res, 0, j));
					}
				}
				PQclear(res);
				return rec;
		});
	}

	//executes SQL that returns a single row with a single column containing a JSON response when data is available
	std::string get_json_response(const std::string& dbname, const std::string &sql)
	{
		return db_exec<std::string>(dbname, sql, [](PGresult *res) {
				std::string json {R"({"status":"EMPTY"})"};
				if (PQntuples(res) && !PQgetisnull(res, 0, 0)) 
					json = std::format(R"({{"status":"OK","data":{}}})", PQgetvalue(res, 0, 0));
				PQclear(res);
				return json;
		});
	}
}
