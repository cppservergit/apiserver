#include "logger.h"

namespace logger 
{
	void log(std::string_view source, std::string_view level, std::string_view msg, std::string_view x_request_id) noexcept
	{
		const auto json {std::format(R"({{"source":"{}","level":"{}","msg":"{}","thread":"{}","x-request-id":"{}"}}{})",
			source, level, msg, pthread_self(), x_request_id, '\n')};
		
		std::clog << json; //thread-safe
	}
}

