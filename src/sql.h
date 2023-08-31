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
#include <libpq-fe.h>
#include "logger.h"
#include "env.h"

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
	
	void exec_sql(const std::string& dbname, const std::string& sql);
	bool has_rows(const std::string& dbname, const std::string &sql);
	std::unordered_map<std::string, std::string> get_record(const std::string& dbname, const std::string& sql);
	std::string get_json_response(const std::string& dbname, const std::string &sql);
}

#endif /* SQL_H_ */
