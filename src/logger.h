/*
 * logger - JSON log output to stderr for Grafana Loki
 *
 *  Created on: Feb 21, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef LOGGER_H_
#define LOGGER_H_

#include <string>
#include <string_view>
#include <thread>
#include <iostream>
#include <sstream>
#include <format>

namespace logger
{
	void log(std::string_view source, std::string_view level, std::string_view msg, std::string_view x_request_id = "") noexcept;
}

#endif /* LOGGER_H_ */
