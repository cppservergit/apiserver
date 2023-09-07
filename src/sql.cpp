#include "sql.h"

namespace 
{
	constexpr int max_retries {3};
	const std::string LOGGER_SRC {"sql-odbc"};
	
	std::pair<std::string, std::string> get_error_msg(SQLHENV henv, SQLHDBC hdbc, SQLHSTMT hstmt) noexcept
	{
	    unsigned char szSQLSTATE[10];
	    SDWORD nErr;
	    unsigned char msg[SQL_MAX_MESSAGE_LENGTH + 1];
	    SWORD cbmsg;
	    SQLError(henv, hdbc, hstmt, szSQLSTATE, &nErr, msg, sizeof(msg), &cbmsg);
		const std::string sqlState {reinterpret_cast< char const* >(szSQLSTATE)};
		const std::string sqlErrorMsg {reinterpret_cast< char const* >(msg)};
		return std::make_pair(sqlErrorMsg, sqlState);
	}

	struct col_info {
		std::string colname;
		SQLSMALLINT dataType{0};
		SQLLEN dataBufferSize{0};
		SQLLEN dataSize{0};
		std::vector<SQLCHAR> data;

		col_info(std::string _colname, SQLSMALLINT _dataType, SQLLEN _dataBufferSize ):
			colname{_colname},
			dataType{_dataType},
			dataBufferSize{_dataBufferSize}
		{
			data.resize(dataBufferSize);
		};
	};

	inline std::vector<col_info> bind_cols(SQLHSTMT hstmt, SQLSMALLINT& numCols) {
		
		std::vector<col_info> cols;
		cols.reserve( numCols );

		for (int i = 0; i < numCols; i++) {
			SQLCHAR colname[50];
			SQLSMALLINT NameLength, dataType, DecimalDigits, Nullable;
			SQLULEN ColumnSize;
			SQLLEN displaySize;
			SQLDescribeCol(hstmt, i + 1, colname, sizeof(colname), &NameLength, &dataType, &ColumnSize, &DecimalDigits, &Nullable);
			SQLColAttribute(hstmt, i + 1, SQL_DESC_DISPLAY_SIZE, NULL, 0, NULL, &displaySize);
			displaySize++;
			col_info& col = cols.emplace_back( reinterpret_cast<char*>(colname), dataType, displaySize );
			SQLBindCol(hstmt, i + 1, SQL_C_CHAR, &col.data[0], col.dataBufferSize, &col.dataSize);
		}
		
		return cols;
	}

	struct dbutil 
	{
		
		std::string m_dbconnstr;
		SQLHENV henv = SQL_NULL_HENV;
		SQLHDBC hdbc = SQL_NULL_HDBC;
		SQLHSTMT hstmt = SQL_NULL_HSTMT;
				
		dbutil() = default;
		dbutil(dbutil &&source) = delete;
		dbutil(const dbutil &source) = delete;
		dbutil& operator =(const dbutil& source) = delete;
		dbutil& operator=(dbutil&& source) = delete;
		
		explicit dbutil(const std::string& conn_info) noexcept: m_dbconnstr{conn_info}
		{
			RETCODE rc {SQL_SUCCESS};
			rc = SQLAllocHandle ( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv );
			if ( rc != SQL_SUCCESS ) {
				logger::log(LOGGER_SRC, "error", "SQLAllocHandle failed", true);
			}

			rc = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3 , 0 );
			if ( rc != SQL_SUCCESS ) {
				logger::log(LOGGER_SRC, "error", "SQLSetEnvAttr failed to set ODBC version", true);
			}

			SQLCHAR* dsn = (SQLCHAR*)m_dbconnstr.c_str();
			SQLSMALLINT bufflen;
			rc = SQLAllocHandle (SQL_HANDLE_DBC, henv, &hdbc);
		
			rc = SQLDriverConnect(hdbc, NULL, dsn, SQL_NTS, NULL, 0, &bufflen, SQL_DRIVER_NOPROMPT);
			if (rc!=SQL_SUCCESS && rc!=SQL_SUCCESS_WITH_INFO) {
				auto [error, sqlstate] {get_error_msg(henv, hdbc, hstmt)};
				logger::log(LOGGER_SRC, "error", "SQLDriverConnect failed: $1", {error}, true);
			}

			rc = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
		}
		
		~dbutil() {
			if (henv) {
				logger::log(LOGGER_SRC, "debug", "releasing odbc resources", true);
				SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
				SQLDisconnect(hdbc);
				SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
				SQLFreeHandle( SQL_HANDLE_ENV, henv );
			}
		}
	
		void reset_connection()
		{
			logger::log(LOGGER_SRC, "warn", "resetting odbc connection", true);
			SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
			SQLDisconnect(hdbc);
			SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
			SQLFreeHandle( SQL_HANDLE_ENV, henv );
			RETCODE rc {SQL_SUCCESS};
			rc = SQLAllocHandle ( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv );
			if ( rc != SQL_SUCCESS ) {
				logger::log(LOGGER_SRC, "error", "SQLAllocHandle failed", true);
			}

			rc = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3 , 0 );
			if ( rc != SQL_SUCCESS ) {
				logger::log(LOGGER_SRC, "error", "SQLSetEnvAttr failed to set ODBC version", true);
			}

			SQLCHAR* dsn = (SQLCHAR*)m_dbconnstr.c_str();
			SQLSMALLINT bufflen;
			rc = SQLAllocHandle (SQL_HANDLE_DBC, henv, &hdbc);
		
			rc = SQLDriverConnect(hdbc, NULL, dsn, SQL_NTS, NULL, 0, &bufflen, SQL_DRIVER_NOPROMPT);
			if (rc!=SQL_SUCCESS && rc!=SQL_SUCCESS_WITH_INFO) {
				auto [error, sqlstate] {get_error_msg(henv, hdbc, hstmt)};
				logger::log(LOGGER_SRC, "error", "SQLDriverConnect failed: $1", {error}, true);
			}

			rc = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);				
		}
	
	};

	sql::recordset get_recordset(SQLHSTMT hstmt) 
	{
		sql::recordset rs;
		SQLSMALLINT numCols ;
		SQLNumResultCols( hstmt, &numCols );
		if (numCols>0) {
			auto cols = bind_cols( hstmt, numCols );
			while ( SQLFetch( hstmt )!=SQL_NO_DATA ) {
				sql::record rec;
				rec.reserve( numCols );
				for ( auto& col: cols ) {
					if (col.dataSize > 0) {
						rec.try_emplace(col.colname, reinterpret_cast<char*>(&col.data[0]));
						//rec[col.colname] = reinterpret_cast<char*>(&col.data[0]);
					} else {
						rec.try_emplace(col.colname, "");
						//rec[col.colname] = "";
					}
				}
				rs.push_back(rec);
			}
		}
		return rs;
	}	

	void get_json_array(SQLHSTMT hstmt, std::string &json) {
		json.append("[");
		SQLSMALLINT numCols{0};
		SQLNumResultCols( hstmt, &numCols );
		if (numCols > 0) {
			auto cols = bind_cols( hstmt, numCols );
			while (SQLFetch(hstmt)!=SQL_NO_DATA) {
				json.append("{");
				for (auto& col: cols) {
					json.append("\"").append(col.colname).append("\":");
					if ( col.dataSize > 0 ) {
						if (col.dataType==SQL_TYPE_DATE || col.dataType==SQL_VARCHAR || col.dataType==SQL_WVARCHAR || col.dataType==SQL_CHAR) {
							json.append("\"").append(  reinterpret_cast<char const*>(&col.data[0]) ).append("\"");
						} else {
							json.append( reinterpret_cast<char const*>(&col.data[0]) );
						}
					} else {
						json.append("\"\"");
					}
					json.append(",");
				}
				json.pop_back();
				json.append("},");
			}
			if (json.back() == ',')
				json.pop_back();
		}
	    json.append("]");
	}

	dbutil& getdb(const std::string& dbname, bool reset = false)
	{
		thread_local std::unordered_map<std::string, dbutil, util::string_hash, std::equal_to<>> dbconns;
		if (!dbconns.contains(dbname)) {
			std::string connstr{env::get_str(dbname)};
			if (!connstr.empty()) {
				auto [iter, success] = dbconns.try_emplace(dbname, connstr);
				return iter->second;
			} else {
				throw sql::database_exception(logger::format("getdb() -> invalid dbname: $1", {dbname}));
			}
		} else {
			if (reset)
				dbconns[dbname].reset_connection();
			return dbconns[dbname];
		}
	}
	
	inline void retry(RETCODE rc, const std::string& dbname, dbutil& db, int& retries, const std::string& sql)
	{
		auto [error, sqlstate] {get_error_msg(db.henv, db.hdbc, db.hstmt)};
		if (sqlstate == "01000" || sqlstate == "08S01" || rc == SQL_INVALID_HANDLE) {
			if (retries == max_retries) {
				throw sql::database_exception(logger::format("retry() -> cannot connect to database:: $1", {dbname}));
			} else {
				retries++;
				getdb(dbname, true);
			}
		} else {
			throw sql::database_exception(logger::format("db_exec() $1 -> sql: $2", {error, sql}));
		}
	}	
	
	template<typename T, class FN>
	T db_exec(const std::string& dbname, const std::string& sql, FN func) 
	{
		SQLCHAR* sqlcmd = (SQLCHAR*)sql.c_str();
		RETCODE rc {SQL_SUCCESS};
		int retries {0};

		while (true) {
			auto& db = getdb(dbname);
			rc = SQLExecDirect(db.hstmt, sqlcmd, SQL_NTS);
			if (rc != SQL_SUCCESS  && rc != SQL_NO_DATA)
				retry(rc, dbname, db, retries, sql);
			else 
				return func(db.hstmt);
		}
	}	
	
}

namespace sql 
{
	bool has_rows(const std::string& dbname, const std::string& sql)
	{
		return db_exec<bool>(dbname, sql, [](SQLHSTMT hstmt) {
			recordset rs {get_recordset(hstmt)};
			SQLFreeStmt(hstmt, SQL_CLOSE);
			SQLFreeStmt(hstmt, SQL_UNBIND);
			return (!rs.empty());
		});
	}

	record get_record(const std::string& dbname, const std::string& sql)
	{
		return db_exec<record>(dbname, sql, [](SQLHSTMT hstmt) {
			record rec;
			recordset rs {get_recordset(hstmt)};
			SQLFreeStmt(hstmt, SQL_CLOSE);
			SQLFreeStmt(hstmt, SQL_UNBIND);
			if (!rs.empty())
				rec = rs[0];
			return rec;
		});
	}
	
	std::string get_json_response(const std::string& dbname, const std::string &sql, bool useDataPrefix, const std::string &prefixName)
	{
		return db_exec<std::string>(dbname, sql, [useDataPrefix, &prefixName](SQLHSTMT hstmt) {
			std::string json; 
			json.reserve(16383);
			if (useDataPrefix) {
				json.append( R"({"status":"OK",)" );
				json.append("\"");
				json.append(prefixName);
				json.append("\":");
			}
			get_json_array(hstmt, json);
			if (useDataPrefix)
				json.append("}");			
			SQLFreeStmt(hstmt, SQL_CLOSE);
			SQLFreeStmt(hstmt, SQL_UNBIND);
			return json;
		});
	}

	std::string get_json_response(const std::string& dbname, const std::string &sql, const std::vector<std::string> &varNames, const std::string &prefixName) 
	{
		return db_exec<std::string>(dbname, sql, [&varNames, &prefixName](SQLHSTMT hstmt) {
			std::string json; 
			json.reserve(16383);
			int rowsetCounter{0};
			json.append(R"({"status":"OK",)");
			json.append("\"");
			json.append(prefixName);
			json.append("\":{");
			do {
				json.append( "\"");
				json.append(varNames[rowsetCounter]);
				json.append("\":");
				get_json_array(hstmt, json);
				json.append(",");
				++rowsetCounter;
			} while (SQLMoreResults(hstmt) == SQL_SUCCESS);
			json.pop_back(); //remove last coma ","
			json.append("}}");
			SQLFreeStmt(hstmt, SQL_CLOSE);
			SQLFreeStmt(hstmt, SQL_UNBIND);
			return json;
		});
	}
	
	void exec_sql(const std::string& dbname, const std::string& sql)
	{
		return db_exec<void>(dbname, sql, [](SQLHSTMT hstmt) {
				SQLFreeStmt(hstmt, SQL_CLOSE);
		});
	}
}


