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

namespace json
{
	constexpr void trim(std::string_view& sv, const char* chars = " ") noexcept
	{
		if (sv.empty()) return;
		sv.remove_prefix(std::min(sv.find_first_not_of(chars), sv.size()));
		if (auto pos {sv.find_last_not_of(chars)}; pos != std::string_view::npos)
			sv.remove_suffix(sv.size() - (sv.find_last_not_of(chars) + 1));
	}

	constexpr std::pair<std::string_view, std::string_view> split_value(std::string_view line)
	{
		//separate key, value and remove quotes from each one
		if (const auto newpos = line.find(":", 0); newpos != std::string_view::npos) {
			std::string_view header_name {line.substr(0,  newpos)};
			std::string_view header_value {line.substr(newpos + 1,  line.size() - newpos)};
			trim(header_name);
			trim(header_value);
			trim(header_name, "\"");
			trim(header_value, "\"");
			return std::make_pair(header_name, header_value);
		} 
		return std::make_pair("", "");
	}

	constexpr std::unordered_map<std::string_view, std::string_view> parse(std::string_view json)
	{
		std::unordered_map<std::string_view, std::string_view> fields;
		const std::string_view body {json.substr(1, json.size() -2)}; //remove curly braces
		const std::string delim{","};
		for (const auto& word : std::views::split(body, delim)) {
			const auto [name, value] {split_value(std::string_view{word})};
			fields.try_emplace(name, value);
		}   
		return fields;
	}
}

#endif /* JSON_H_ */