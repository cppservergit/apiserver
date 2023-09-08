/*
 * logger - json log output to stderr and loki (optional using loki module), depends on env, loki
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
#include <thread>
#include <iostream>
#include <vector>
#include <algorithm>

namespace logger
{
	void log(std::string_view source, std::string_view level, std::string msg, bool add_thread_id = false, std::string_view x_request_id = "") noexcept;
	
	template<typename T>
	std::string format(std::string msg, const std::initializer_list<T>& values) noexcept
	{
		int i{1};
		for (const auto& v: values) {
			std::string item {"$"};
			item.append(std::to_string(i));
			if (auto pos {msg.find(item)}; pos != std::string::npos)
				msg.replace(pos, item.size(), v);
			++i;
		}
		return msg;
	}

	template<typename T>
	void log(std::string_view source, std::string_view level, std::string msg, const std::initializer_list<T>& values, bool add_thread_id = false, std::string_view x_request_id = "") noexcept
	{
		log(source, level, format(msg, values), add_thread_id, x_request_id);
	}
	
}

#endif /* LOGGER_H_ */
