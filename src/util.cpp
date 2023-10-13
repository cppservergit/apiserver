#include "util.h"

namespace util
{
	std::string today() noexcept
	{
		return std::format("{:%F}", std::chrono::system_clock::now());
	}	
}
