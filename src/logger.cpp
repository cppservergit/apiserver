#include "logger.h"

namespace logger 
{
	void log(std::string_view source, std::string_view level, std::string msg, bool add_thread_id, std::string_view x_request_id) noexcept
	{
		std::ranges::transform(msg, msg.begin(), 
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
		buffer.append(R"({"source":")").append(source).append(R"(",)").append(R"("level":")").append(level).append(R"(","msg":")").append(msg).append(R"(",)");
		
		if (add_thread_id) {
			buffer.append(R"("thread":")").append(std::to_string(pthread_self())).append(R"(",)");
			if (!x_request_id.empty())
				buffer.append(R"("x-request-id":")").append(x_request_id).append(R"(",)");
		}
		
		buffer.pop_back();
		buffer.append("}\n");
		std::clog << buffer;
	}
}

