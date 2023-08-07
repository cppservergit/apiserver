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
#include <cstdlib>
#include <openssl/hmac.h>
#include "logger.h"
#include "env.h"

namespace jwt
{
	std::string get_token(const std::string& userlogin, const std::string& mail, const std::string& roles) noexcept;
	bool is_valid(const std::string& token);
	void clear();
	std::string user_get_login() noexcept;
	std::string user_get_mail() noexcept;
	std::string user_get_roles() noexcept;	
}

#endif /* JWT_H_ */
