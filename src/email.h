/*
 * email - send mail using libcurl (TLS-openssl)
 *
 *  Created on: June 6, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef EMAIL_H_
#define EMAIL_H_

#include <curl/curl.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <iomanip>
#include <sstream>
#include <array>
#include <format>
#include <chrono>
#include "logger.h"
#include "httputils.h"

namespace smtp
{
	struct mail
	{
			explicit mail(const std::string& server, const std::string& user, const std::string& pwd);
			void send() noexcept;
			void add_attachment(const std::string& path, const std::string& filename, const std::string& encoding = "base64" ) noexcept;
			void add_attachment(const std::string& path) noexcept;
			
			void set_to(std::string_view  _to) noexcept;
			void set_cc(std::string_view  _cc) noexcept;
			void set_subject(std::string_view  _subject) noexcept;
			void set_body(std::string_view  _body) noexcept;
			void set_debug(bool _debug) noexcept;
			void set_x_request_id(std::string_view  _id) noexcept;
			
		private:
			void add_documents() noexcept;
			void build_message() noexcept;
			
			CURL *curl{nullptr};
			CURLcode res = CURLE_OK;
			struct curl_slist *headers = nullptr;
			struct curl_slist *recipients = nullptr;
			curl_mime *mime;
			curl_mimepart *part;
			
			std::string server_url;
			std::string username;
			std::string password;

			std::string to;
			std::string cc;
			std::string subject;
			std::string body;
			bool debug_mode{false};
			std::string x_request_id;
			
			struct attachment
			{
				std::string filesystem_path;
				std::string filename;
				std::string encoding{"base64"};
			};
			std::vector<attachment> documents;
	};
}

#endif /* EMAIL_H_ */
