/*
 * json - minimal JSON parser for simple JSON objects like {"a":"value_a","b":"value_b","c":195.76}
 *
 *  Created on: Feb 21, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
 
#ifndef JSON_H_
#define JSON_H_

#include <string_view>
#include <ranges>
#include <unordered_map>
#include "util.h"

namespace json
{
	class invalid_json_exception
	{
		public:
			explicit invalid_json_exception(const std::string& _msg): m_msg {_msg} {}
			std::string what() const noexcept {
				std::string error_msg{m_msg};
				return error_msg;
			}
		private:
            std::string m_msg;
	};		

    constexpr void extract_value(std::string& s) noexcept
    {
        if (auto pos1 = s.find("\""); pos1 != std::string::npos) {
            pos1 += 1;
			if (auto pos2 = s.find("\"", pos1); pos2 != std::string::npos)
                s = s.substr(pos1, pos2 - pos1); 
            return;
        }
        if (s.empty()) return;
        s.erase(0, s.find_first_not_of(" "));
        s.erase(s.find_last_not_of(" ") + 1);
    }

	constexpr std::pair<std::string, std::string> split_value(std::string_view line)
	{
		if (const auto newpos = line.find(":", 0); newpos != std::string_view::npos) {
			std::string header_name {line.substr(0,  newpos)};
			std::string header_value {line.substr(newpos + 1,  line.size() - newpos)};
			extract_value(header_name);
			extract_value(header_value);
			return std::make_pair(header_name, header_value);
		} 
		return std::make_pair("", "");
	}

	inline auto parse(std::string_view json)
	{
		std::unordered_map<std::string, std::string, util::string_hash, std::equal_to<>> fields;
        if (auto pos1 = json.find("{"); pos1 != std::string::npos) {
            pos1 += 1;
			if (auto pos2 = json.find("}", pos1); pos2 != std::string::npos) {
                const std::string_view body {json.substr(pos1, pos2 - pos1)}; 
                const std::string delim{","};
                for (const auto& word : std::views::split(body, delim)) {
                    const auto& [name, value] {split_value(std::string_view{word})};
                    fields.try_emplace(name, value);
		        }   
			} else
				throw invalid_json_exception("invalid JSON format - lacks closing brace");
		} else
			throw invalid_json_exception("invalid JSON format - lacks opening brace");
		if (fields.empty())
			throw invalid_json_exception("invalid JSON format - no attributes available inside the braces");
		return fields;
	}	
}

#endif /* JSON_H_ */