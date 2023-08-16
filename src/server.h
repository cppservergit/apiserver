/*
 * server - epoll single-thread, workers-pool server
 *
 *  Created on: July 18, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef SERVER_H_
#define SERVER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/signalfd.h>
#include <netinet/tcp.h>
#include <iomanip>
#include <cstring> 
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <stop_token>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <charconv>
#include <functional>
#include <filesystem>
#include "env.h"
#include "logger.h"
#include "login.h"
#include "sql.h"
#include "httputils.h"
#include "jwt.h"
#include "email.h"

namespace server
{
	struct webapi_path
	{
		public:
			webapi_path(const std::string& _path): m_path{_path} 
			{
				if (!_path.starts_with("/") || _path.ends_with("/") || _path.contains(" ") || _path.contains("//"))
					throw std::runtime_error("Invalid path: " + m_path);
				std::string valid_chars{"abcdefghijklmnopqrstuvwxyz_-0123456789/"};
				for(const char& c: m_path)
					if (!valid_chars.contains(c))
						throw std::runtime_error("WebAPI registration error -> invalid path: " + m_path);
			}
			auto get_path() const noexcept
			{
				return m_path;
			}

		private: 
			std::string m_path;
	};
	
	void start() noexcept;
	
	void register_webapi(
		const webapi_path& _path, 
		const std::string& _description, 
		http::verb _verb, 
		const std::vector<http::input_rule>& _rules, 
		const std::vector<std::string>& _roles, 
		std::function<void(http::request&)> _fn,
		bool _is_secure = true
	);

	void register_webapi(
		const webapi_path& _path, 
		const std::string& _description, 
		http::verb _verb, 
		std::function<void(http::request&)> _fn,
		bool _is_secure = true
	);
	
	void send_mail(const std::string& to, const std::string& subject, const std::string& body);
	void send_mail(const std::string& to, const std::string& cc, const std::string& subject, const std::string& body);
	void send_mail(const std::string& to, const std::string& cc, const std::string& subject, const std::string& body, const std::string& attachment, const std::string& attachment_filename = "");
}

#endif /* SERVER_H_ */
