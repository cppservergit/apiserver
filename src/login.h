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
#include <libpq-fe.h>
#include "env.h"
#include "logger.h"

namespace login
{
	bool bind(const std::string& login, const std::string& password);
	std::string get_email() noexcept;
	std::string get_display_name() noexcept;
	std::string get_roles() noexcept;
}

#endif /* LOGIN_H_ */
