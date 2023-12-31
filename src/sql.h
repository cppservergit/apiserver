/*
 * sql - json microservices PGSQL utility API - depends on libpq (pgsql native client API)
 *
 *  Created on: Feb 23, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef SQL_H_
#define SQL_H_

#include <string>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <postgresql/libpq-fe.h>
#include "logger.h"
#include "env.h"
#include "util.h"

namespace sql
{
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
	
	//executes a query that doesn't return rows (data modification query)
	void exec_sql(const std::string& dbname, const std::string& sql);
	//returns true if the query retuned 1+ row
	bool has_rows(const std::string& dbname, const std::string &sql);
	//returns only the first rows of a resultset, use of "limit 1" or "where col=pk" in the query is recommended
	std::unordered_map<std::string, std::string, util::string_hash, std::equal_to<>> get_record(const std::string& dbname, const std::string& sql);
	//executes SQL that returns a single row with a single column containing a JSON response when data is available
	std::string get_json_response(const std::string& dbname, const std::string &sql);
}

#endif /* SQL_H_ */
