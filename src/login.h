/*
 * login - login adapter using a database function - depends on libpq (pgsql native client API)
 *
 *  Created on: Feb 21, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef LOGIN_H_
#define LOGIN_H_

#include <string>
#include <iostream>
#include <unordered_map>
#include "env.h"
#include "logger.h"
#include "sql.h"

namespace login
{
	struct login_result
	{
		public:
			login_result(bool _result, const std::string& _name, const std::string& _mail,const std::string& _roles) noexcept;
			std::string get_email() const noexcept;
			std::string get_display_name() const noexcept;
			std::string get_roles() const noexcept;
			bool ok() noexcept;
		private:
			bool result;
			std::string display_name;
			std::string email;
			std::string roles;
	};	
	login_result bind(const std::string& login, const std::string& password);
	
}

#endif /* LOGIN_H_ */
