/*
 * env - read environment variables for cppserver program
 *
 *  Created on: Feb 21, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef ENV_H_
#define ENV_H_

#include <string>
#include <cstdlib>
#include <charconv>
#include <format>
#include "logger.h"

namespace env 
{
	unsigned short int port() noexcept;
	unsigned short int http_log_enabled() noexcept;
	unsigned short int pool_size() noexcept;
	unsigned short int login_log_enabled() noexcept;
	unsigned short int jwt_expiration() noexcept;
	std::string get_str(const std::string& name) noexcept;
}

#endif /* ENV_H_ */
