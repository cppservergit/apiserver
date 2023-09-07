/*
 * sql - json microservices ODBC utility API - depends on  unixodbc-dev
 *
 *  Created on: March 23, 2023
 *      Author: Martín Córdova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef SQLODBC_H_
#define SQLODBC_H_

#include <sql.h>
#include <sqlext.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include "util.h"
#include "logger.h"
#include "env.h"

namespace sql
{
	using record    = std::unordered_map<std::string, std::string, util::string_hash, std::equal_to<>>;
	using recordset = std::vector<record>;
	
	class database_exception
	{
		public:
			explicit database_exception(std::string_view _msg): m_msg {_msg} {}
			std::string what() const noexcept {
				return m_msg;
			}
		private:
            std::string m_msg;
	};
	
	std::string get_json_response(const std::string& dbname, const std::string &sql, bool useDataPrefix=true, const std::string &prefixName="data");
	std::string get_json_response(const std::string& dbname, const std::string &sql, const std::vector<std::string> &varNames, const std::string &prefixName="data");
	void exec_sql(const std::string& dbname, const std::string& sql);
	bool has_rows(const std::string& dbname, const std::string &sql);
	record get_record(const std::string& dbname, const std::string& sql);
}

#endif /* SQLODBC_H_ */
