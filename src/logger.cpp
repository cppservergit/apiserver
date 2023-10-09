#include "logger.h"

namespace logger 
{
	void log(std::string_view source, std::string_view level, std::string_view msg, std::string_view x_request_id) noexcept
	{
		//workaround: GCC-13 does not support std::thread::id formatter
		constexpr auto this_thread_id = []() {
			std::ostringstream ss;
			ss << std::this_thread::get_id();
			return ss.str();
		};
		
		const auto json {std::format(R"({{"source":"{}","level":"{}","msg":"{}","thread":"{}","x-request-id":"{}"}})",
			source, level, msg, this_thread_id(), x_request_id) + "\n"};
		
		std::clog << json; //thread-safe
	}
}

