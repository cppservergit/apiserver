
/*
 * httputils - provides http utility abstractions for epoll server and microservice engine
 *
 *  Created on: Feb 21, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef HTTPUTILS_H_
#define HTTPUTILS_H_

#include <string>
#include <string_view>
#include <unordered_map>
#include <algorithm>
#include <fstream>
#include <random>
#include <cstdio>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <array>
#include <functional>
#include <sys/socket.h>
#include "logger.h"
#include "jwt.h"

namespace http
{
	const std::string blob_path {"/var/blobs/"};
	
	std::string get_content_type(const std::string& filename) noexcept;
	std::string get_response_date() noexcept;

	enum class verb {GET, POST};

	class invalid_input_exception
	{
		public:
			std::string what() const noexcept
			{
				return "Invalid HTTP request input parameter: " + field_name;
			}
			invalid_input_exception(const std::string& _name, const std::string& _errmsg): 
				field_name{_name}, error_description{_errmsg} { }
			auto get_field_name() const { return field_name; }
			auto get_error_description() const { return error_description; }
		private:
			std::string field_name;
			std::string error_description;
	};

	class login_required_exception
	{
		public:
			login_required_exception(const std::string& _remote_ip, const std::string& _reason)
			: m_remote_ip {_remote_ip}, m_reason(_reason) {}
			std::string what() const noexcept {
				return "Authentication required from IP: " + m_remote_ip + " reason: " + m_reason;
			}
		private:
            std::string m_remote_ip;
			std::string m_reason;
	};

	class access_denied_exception
	{
		public:
			access_denied_exception(const std::string& _remote_ip, const std::string& _reason)
			: m_remote_ip {_remote_ip}, m_reason(_reason) {}
			std::string what() const noexcept {
				return "Access denied for user: " + jwt::user_get_login() + " from IP: " + m_remote_ip + " reason: " + m_reason;
			}
		private:
            std::string m_remote_ip;
            std::string m_reason;		
	};

	class method_not_allowed_exception
	{
		public:
			method_not_allowed_exception(const std::string& _method): m_method {_method} {}
			std::string what() const noexcept {
				std::string error_msg{"HTTP method not allowed: " + m_method};
				return error_msg;
			}
		private:
            std::string m_method;
	};
	
	class resource_not_found_exception
	{
		public:
			resource_not_found_exception(const std::string& _msg): m_message {_msg} {}
			std::string what() const noexcept {
				std::string error_msg{"Resource not found: " + m_message};
				return error_msg;
			}
		private:
            std::string m_message;
	};	
	
	enum class field_type {
							INTEGER = 1,
							DOUBLE = 2,
							STRING = 3,
							DATE = 4 //yyyy-mm-dd
						};

	struct input_rule {
		public:
			input_rule(std::string n, field_type d, bool r): name{n}, datatype{d}, required{r} {  }
			auto get_name() const {return name;}
			auto get_type() const {return datatype;}
			auto get_required() const {return required;}
		private:
			std::string name;
			field_type datatype;
			bool required;
	};
	
	struct form_field 
	{
		std::string name;
		std::string filename;
		std::string content_type;
		std::string data;
	};

	struct response_stream {
	  public:	
		response_stream(int size);
		response_stream();
		response_stream& operator <<(std::string data);
		response_stream& operator <<(const char* data);
		response_stream& operator <<(size_t data);
		void set_body(const std::string& body, const std::string& content_type = "application/json", int max_age = 0);
		void set_content_disposition(const std::string& disposition);
		void set_origin(const std::string& origin);
		std::string_view view() noexcept;
		size_t size() noexcept;
		const char* c_str() noexcept;
		void append(const char* data, size_t len) noexcept;
		const char* data() noexcept;
		void clear() noexcept;
		bool write(int fd) noexcept; 
	  private:
		int _pos1 {0};
		std::string _buffer{""};
		std::string _content_disposition{""};
		std::string _origin{""};
	};
	
	struct request {
	  public:
		int epoll_fd;
		int fd; //socket fd
		size_t bodyStartPos{0};
		size_t contentLength{0};
		bool isMultipart{false};
		std::string method{""};
		std::string queryString{""};
		std::string path{""};
		std::string boundary{""};
		std::string cookie{""};
		std::string token{""};
		int errcode{0};
		std::string errmsg{""};
		std::string remote_ip;
		std::string origin{"null"};
		std::string payload;
		std::unordered_map<std::string, std::string> headers;
		std::unordered_map<std::string, std::string> params;
		std::vector<input_rule> input_rules;
		response_stream response;
		request();
		request(int epollfd, int fdes, const char* ip);
		~request();
		void clear();
		void parse();
		bool eof();
		std::string get_header(const std::string& name) const;
		std::string get_param(const std::string& name) const;
		void enforce(verb v);
		void enforce(const std::vector<input_rule>& rules);
		void enforce(const std::string& id, const std::string& error_description, std::function<bool()> fn);
		std::string get_sql(std::string sql, const std::string& userlogin = "");
		void check_security(const std::vector<std::string>& roles = {});
		std::string get_mail_body(const std::string& template_file, const std::string& userlogin = "Undefined");
		std::string replace_params(const std::string& template_msg);
	  private:
		std::string_view get_cookie(std::string_view cookieHdr);
		std::string lowercase(std::string s) noexcept;	
		std::string decode_param(const std::string &value) noexcept;
		void parse_query_string(std::string_view qs) noexcept;	
		std::string get_part_content_type(std::string value);
		std::pair<std::string, std::string> get_part_field(std::string value);
		std::vector<form_field> parse_multipart();
	};	
}

#endif /* HTTPUTILS_H_ */

