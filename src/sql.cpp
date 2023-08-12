#include "sql.h"

namespace 
{
	constexpr int max_retries {3};
	const std::string LOGGER_SRC {"sql-odbc"};
	thread_local std::string m_sqlstate{""};

	using record    = std::unordered_map<std::string, std::string>;
	using recordset = std::vector<record>;

	std::string get_error_msg(SQLHENV henv, SQLHDBC hdbc, SQLHSTMT hstmt, const std::string& sql="") 
	{
	    unsigned char szSQLSTATE[10];
	    SDWORD nErr;
	    unsigned char msg[SQL_MAX_MESSAGE_LENGTH + 1];
	    SWORD cbmsg;
	    std::stringstream errMsg;
	    SQLError(henv, hdbc, hstmt, szSQLSTATE, &nErr, msg, sizeof(msg), &cbmsg);
		const std::string sqlState( reinterpret_cast< char const* >(szSQLSTATE) );
		const std::string sqlErrorMsg( reinterpret_cast< char const* >(msg) );
		errMsg << sqlState << " " << sqlErrorMsg; 
		if (!sql.empty()) 
			errMsg << " SQL: " << sql;
		m_sqlstate = sqlState;
		return errMsg.str();
	}

	struct col_info {
		
		std::string colname;
		SQLSMALLINT dataType{0};
		SQLLEN dataBufferSize{0};
		SQLLEN dataSize{0};
		std::vector<SQLCHAR> data;

		col_info(std::string _colname, SQLSMALLINT _dataType, SQLLEN _dataBufferSize ):
			colname{ _colname },
			dataType{ _dataType },
			dataBufferSize{ _dataBufferSize }
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
				
		dbutil() 
		{
			logger::log(LOGGER_SRC, "debug", "empty constructor invoked", true);
		}
		
		dbutil(const std::string& conn_info): m_dbconnstr{conn_info}
		{
			RETCODE rc {SQL_SUCCESS};
			rc = SQLAllocHandle ( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv );
			if ( rc != SQL_SUCCESS ) {
				logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + " SQLAllocHandle failed", true);
			}

			rc = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3 , 0 );
			if ( rc != SQL_SUCCESS ) {
				logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + " SQLSetEnvAttr failed to set ODBC version", true);
			}

			SQLCHAR* dsn = (SQLCHAR*)m_dbconnstr.c_str();
			SQLSMALLINT bufflen;
			rc = SQLAllocHandle (SQL_HANDLE_DBC, henv, &hdbc);
		
			rc = SQLDriverConnect(hdbc, NULL, dsn, SQL_NTS, NULL, 0, &bufflen, SQL_DRIVER_NOPROMPT);
			if (rc!=SQL_SUCCESS && rc!=SQL_SUCCESS_WITH_INFO) {
				logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + " SQLDriverConnect failed: " + get_error_msg(henv, hdbc, hstmt), true);
			}

			rc = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
		}
		
		dbutil(dbutil &&source) : m_dbconnstr{source.m_dbconnstr}, henv{source.henv}, hdbc{source.hdbc}, hstmt{source.hstmt}
		{
			source.henv = 0;
			source.hdbc = 0;
			source.hstmt = 0;
		}

		dbutil(const dbutil &source) : m_dbconnstr{source.m_dbconnstr}, henv{source.henv}, hdbc{source.hdbc}, hstmt{source.hstmt}
		{
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
				logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + " SQLAllocHandle failed", true);
			}

			rc = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3 , 0 );
			if ( rc != SQL_SUCCESS ) {
				logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + " SQLSetEnvAttr failed to set ODBC version", true);
			}

			SQLCHAR* dsn = (SQLCHAR*)m_dbconnstr.c_str();
			SQLSMALLINT bufflen;
			rc = SQLAllocHandle (SQL_HANDLE_DBC, henv, &hdbc);
		
			rc = SQLDriverConnect(hdbc, NULL, dsn, SQL_NTS, NULL, 0, &bufflen, SQL_DRIVER_NOPROMPT);
			if (rc!=SQL_SUCCESS && rc!=SQL_SUCCESS_WITH_INFO) {
				logger::log(LOGGER_SRC, "error", std::string(__FUNCTION__) + " SQLDriverConnect failed: " + get_error_msg(henv, hdbc, hstmt), true);
			}

			rc = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);				
		}
	
	};

	thread_local  std::unordered_map<std::string, dbutil> dbconns;

	recordset get_recordset(SQLHSTMT hstmt) 
	{
		recordset rs;
		SQLSMALLINT numCols ;
		SQLNumResultCols( hstmt, &numCols );
		if (numCols>0) {
			auto cols = bind_cols( hstmt, numCols );
			while ( SQLFetch( hstmt )!=SQL_NO_DATA ) {
				record rec;
				rec.reserve( numCols );
				for ( auto& col: cols ) {
					if (col.dataSize > 0) {
						rec[col.colname] = reinterpret_cast<char*>(&col.data[0]);
					} else {
						rec[col.colname] = "";
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

}

namespace sql 
{
	void connect(const std::string& dbname, const std::string& conn_info)
	{
		if (!dbconns.contains(dbname)) { 
			dbconns.insert({dbname, dbutil(conn_info)});
		} else {
			std::string error{std::string(__FUNCTION__) + " duplicated dbname: " + dbname};
			throw std::runtime_error(error.c_str());
		}
	}

	dbutil& getdb(const std::string& dbname)
	{
		if (!dbconns.contains(dbname)) {
			std::string error{std::string(__FUNCTION__) + " invalid dbname: " + dbname};
			throw std::runtime_error(error.c_str());
		}
		return dbconns[dbname];
	}	
	
	bool has_rows(const std::string& dbname, const std::string& sql)
	{
		recordset rs;
		SQLCHAR* sqlcmd = (SQLCHAR*)sql.c_str();
		dbutil& db{getdb(dbname)};
		RETCODE rc {SQL_SUCCESS};
		int retries {0};
		m_sqlstate = "";
		
	retry:		
		rc = SQLExecDirect(db.hstmt, sqlcmd, SQL_NTS);
		if (rc != SQL_SUCCESS) {
			std::string error{std::string(__FUNCTION__) + + " " + get_error_msg(db.henv, db.hdbc, db.hstmt, sql)};
			if (retries < max_retries && (m_sqlstate == "01000" || m_sqlstate == "08S01" || rc == SQL_INVALID_HANDLE)) {
				++retries;
				db.reset_connection();
				goto retry;
			}			
			throw std::runtime_error(error.c_str());				
		} else {
			rs = get_recordset(db.hstmt);
		}

		SQLFreeStmt(db.hstmt, SQL_CLOSE);
		SQLFreeStmt(db.hstmt, SQL_UNBIND);
		return (rs.size() > 0);
	}

	std::unordered_map<std::string, std::string> get_record(const std::string& dbname, const std::string& sql)
	{
		recordset rs;
		record rec;
		SQLCHAR* sqlcmd = (SQLCHAR*)sql.c_str();
		dbutil& db{getdb(dbname)};
		RETCODE rc {SQL_SUCCESS};
		int retries {0};
		m_sqlstate = "";
		
	retry:		
		rc = SQLExecDirect(db.hstmt, sqlcmd, SQL_NTS);

		if (rc != SQL_SUCCESS) {
			std::string error{std::string(__FUNCTION__) + + " " + get_error_msg(db.henv, db.hdbc, db.hstmt, sql)};
			if (retries < max_retries && (m_sqlstate == "01000" || m_sqlstate == "08S01" || rc == SQL_INVALID_HANDLE)) {
				++retries;
				db.reset_connection();
				goto retry;
			}			
			throw std::runtime_error(error.c_str());
		} else {
			rs = get_recordset(db.hstmt);
			if (rs.size())
				rec = rs[0];
		}

		SQLFreeStmt(db.hstmt, SQL_CLOSE);
		SQLFreeStmt(db.hstmt, SQL_UNBIND);
		return rec;
	}
	
	std::string get_json_response(const std::string& dbname, const std::string &sql, bool useDataPrefix, const std::string &prefixName)
	{
		std::string json; json.reserve(16383);
		dbutil& db{getdb(dbname)};
		RETCODE rc{SQL_SUCCESS};		
		SQLCHAR* sqlcmd = (SQLCHAR*)sql.c_str();
		int retries {0};
		m_sqlstate = "";
		
	retry:	
		rc = SQLExecDirect(db.hstmt, sqlcmd, SQL_NTS);
		if (rc != SQL_SUCCESS) {
			std::string error{std::string(__FUNCTION__) + + " " + get_error_msg(db.henv, db.hdbc, db.hstmt, sql)};
			if (retries < max_retries && (m_sqlstate == "01000" || m_sqlstate == "08S01" || rc == SQL_INVALID_HANDLE)) {
				++retries;
				db.reset_connection();
				goto retry;
			}
			throw std::runtime_error(error.c_str());
		} else {
			if (useDataPrefix) {
				json.append( R"({"status":"OK",)" );
				json.append("\"");
				json.append(prefixName);
				json.append("\":");
			}
			get_json_array(db.hstmt, json);
			if (useDataPrefix)
				json.append("}");
		}

		SQLFreeStmt(db.hstmt, SQL_CLOSE);
		SQLFreeStmt(db.hstmt, SQL_UNBIND);
		return json;
	}

	std::string get_json_response(const std::string& dbname, const std::string &sql, const std::vector<std::string> &varNames, const std::string &prefixName) 
	{
		std::string json; json.reserve(16383);
		dbutil& db{getdb(dbname)};
		RETCODE rc{SQL_SUCCESS};		
		SQLCHAR* sqlcmd = (SQLCHAR*)sql.c_str();
		int retries {0};
		m_sqlstate = "";
		
	retry:		
		rc = SQLExecDirect(db.hstmt, sqlcmd, SQL_NTS);
		if (rc != SQL_SUCCESS) {
			std::string error{std::string(__FUNCTION__) + + " " + get_error_msg(db.henv, db.hdbc, db.hstmt, sql)};
			if (retries < max_retries && (m_sqlstate == "01000" || m_sqlstate == "08S01" || rc == SQL_INVALID_HANDLE)) {
				++retries;
				db.reset_connection();
				goto retry;
			}
			throw std::runtime_error(error.c_str());
		} else {
			int rowsetCounter{0};
			json.append(R"({"status":"OK",)");
			json.append("\"");
			json.append(prefixName);
			json.append("\":{");
			do {
				json.append( "\"");
				json.append(varNames[rowsetCounter]);
				json.append("\":");
				get_json_array(db.hstmt, json);
				json.append(",");
				++rowsetCounter;
			} while (SQLMoreResults(db.hstmt) == SQL_SUCCESS);
			json.pop_back(); //remove last coma ","
			json.append("}}");
		}

		SQLFreeStmt(db.hstmt, SQL_CLOSE);
		SQLFreeStmt(db.hstmt, SQL_UNBIND);
		return json;
	}
	
	void exec_sql(const std::string& dbname, const std::string& sql)
	{
		dbutil& db{getdb(dbname)};
		RETCODE rc{SQL_SUCCESS};		
		SQLCHAR* sqlcmd = (SQLCHAR*)sql.c_str();
		int retries {0};
		m_sqlstate = "";
		
	retry:	
		rc = SQLExecDirect(db.hstmt, sqlcmd, SQL_NTS);
		if (rc != SQL_SUCCESS && rc!=SQL_NO_DATA) {
			std::string error{std::string(__FUNCTION__) + + " " + get_error_msg(db.henv, db.hdbc, db.hstmt, sql)};
			if (retries < max_retries && (m_sqlstate == "01000" || m_sqlstate == "08S01" || rc == SQL_INVALID_HANDLE)) {
				++retries;
				db.reset_connection();
				goto retry;
			}
			throw std::runtime_error(error.c_str());
		}

		SQLFreeStmt(db.hstmt, SQL_CLOSE);
	}
}


