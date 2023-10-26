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
#include <json-c/json.h>
#include "util.h"

namespace json
{
	class invalid_json_exception
	{
		public:
			explicit invalid_json_exception(const std::string& _msg): m_msg {_msg} {}
			std::string what() const noexcept {
				return m_msg;
			}
		private:
            std::string m_msg;
	};		

	inline auto parse(std::string_view json)
	{
		std::unordered_map<std::string, std::string, util::string_hash, std::equal_to<>> fields;
		json_object * jobj = json_tokener_parse(json.data());
		if (jobj == nullptr) {
			std::clog << std::format("[DEBUG][JSON] invalid JSON format: {}\n", json);
			throw invalid_json_exception("invalid JSON format, check stderr log for details");
		}
		json_object_object_foreach(jobj, key, val) {
			if (const char* val_ptr {json_object_get_string(val)})
				fields.try_emplace(key, val_ptr);
			else
				fields.try_emplace(key, "");
		}
		json_object_put(jobj);
		return fields;
	}
}

#endif /* JSON_H_ */
