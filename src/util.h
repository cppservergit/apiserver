#ifndef UTIL_H_
#define UTIL_H_

#include <chrono>
#include <format>

namespace util
{
	//taken from https://www.cppstories.com/2021/heterogeneous-access-cpp20/ 
	//addresses issues raised by rule cpp:S6045 from SonarCloud static analyzer
	struct string_hash {
	  using is_transparent = void;
	  [[nodiscard]] size_t operator()(const char *txt) const {
		return std::hash<std::string_view>{}(txt);
	  }
	  [[nodiscard]] size_t operator()(std::string_view txt) const {
		return std::hash<std::string_view>{}(txt);
	  }
	  [[nodiscard]] size_t operator()(const std::string &txt) const {
		return std::hash<std::string>{}(txt);
	  }
	};

	//return date as yyyy-mm-dd
	std::string today() noexcept;
}

#endif /* UTILS_H_ */
