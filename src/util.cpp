#include "util.h"

namespace util
{
	std::string today() noexcept
	{
		std::ostringstream s;
		auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		std::tm tm{};
		gmtime_r(&now, &tm);    
		s << std::put_time(localtime_r(&now, &tm), "%Y-%m-%d");
		return s.str();
	}	
}
