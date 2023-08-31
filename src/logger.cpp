#include "logger.h"

namespace
{
	thread_local std::string request_id;
}

namespace logger 
{
	void set_request_id(std::string_view id) noexcept
	{
		request_id = id;
	}
	
	std::string get_request_id() noexcept
	{
		return request_id;
	}
	
	void log(std::string_view source, std::string_view level, std::string msg, bool add_thread_id) noexcept
	{
		std::transform( msg.begin(), msg.end(), msg.begin(), 
			[](unsigned char c)
			{
				if (c == '\n') c = ' ';
				if (c == '\r') c = ' ';
				if (c == '\t') c = ' ';
				if (c == '"') c = '\'';
				return c; 
			}
		);
		
		std::string buffer{""};
		buffer.reserve(1023);
		buffer.append("{\"source\":\"").append(source).append("\",").append("\"level\":\"").append(level).append("\",\"msg\":\"").append(msg).append("\",");
		
		if (add_thread_id) {
			buffer.append("\"thread\":\"").append(std::to_string(pthread_self())).append("\",");
			if (!request_id.empty())
				buffer.append("\"x-request-id\":\"").append(request_id).append("\",");
		}
		
		buffer.pop_back();
		buffer.append("}\n");
		std::clog << buffer;
	}
	
	void log(std::string_view source, std::string_view level, std::string msg, const std::vector<std::string>& values, bool add_thread_id) noexcept
	{
		int i{1};
		for (const auto& v: values) {
			std::string item {"$"};
			item.append(std::to_string(i));
			if (auto pos {msg.find(item)}; pos != std::string::npos)
				msg.replace(pos, item.size(), v);
			++i;
		}
		log(source, level, msg, add_thread_id);
	}

	std::string format(std::string msg, const std::vector<std::string>& values) noexcept
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
}

