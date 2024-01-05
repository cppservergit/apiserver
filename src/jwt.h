/*
 * jwt - JSON web token
 *
 *  Created on: July 22, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef JWT_H_
#define JWT_H_

#include <string>
#include <vector>
#include <string_view>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <array>
#include <openssl/hmac.h>
#include "logger.h"
#include "env.h"
#include "json.h"

namespace jwt
{
	struct user_info 
	{
		std::string login;
		std::string mail;
		std::string roles;
		time_t exp{0};
	};
	
	std::string get_token(std::string_view username, std::string_view mail, std::string_view roles) noexcept;
	std::pair<bool, user_info> is_valid(const std::string& token);
}

#endif /* JWT_H_ */
