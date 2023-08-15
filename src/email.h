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
#include "logger.h"

namespace smtp
{
	struct mail
	{
		public:
			std::string to;
			std::string cc;
			std::string subject;
			std::string body;
			bool debug_mode{false};
			std::string x_request_id{""};

			mail(const std::string& server, const std::string& user, const std::string& pwd);
			~mail();
			void send() noexcept;
			void add_attachment(const std::string& path, const std::string& filename, const std::string& encoding = "base64" ) noexcept;
			void add_attachment(const std::string& path) noexcept;
			
		private:
			CURL *curl;
			CURLcode res = CURLE_OK;
			struct curl_slist *headers = NULL;
			struct curl_slist *recipients = NULL;
			curl_mime *mime;
			curl_mimepart *part;			
			std::string server_url;
			std::string username;
			std::string password;

			struct attachment
			{
				std::string filesystem_path;
				std::string filename;
				std::string encoding{"base64"};
			};
			std::vector<attachment> documents;

			std::string get_uuid() noexcept; 
			std::string get_response_date() noexcept;
	};
}

#endif /* EMAIL_H_ */
