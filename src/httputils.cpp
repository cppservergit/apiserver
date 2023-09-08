#include "httputils.h"

namespace
{
	/* utility functions */
	std::string lowercase(std::string_view sv) noexcept 
	{
		std::string s {sv};
		std::ranges::transform( s, s.begin(), [](unsigned char c){ return std::tolower(c); } );
		return s;
	}
	
	inline std::string trim(const std::string & source)
	{
		std::string s(source);
		s.erase(0, s.find_first_not_of(" "));
		s.erase(s.find_last_not_of(" ") + 1);
		return s;
	}

	inline bool is_integer(const std::string_view s)
	{
		return std::ranges::find_if(s, [](unsigned char c) { return !std::isdigit(c); }) == s.end();
	}

	inline bool is_double(std::string_view s)
	{
		if (auto d = s.find("."); d!=std::string::npos) {
			auto part1{s.substr(0, d)};
			auto part2{s.substr(d + 1)};
			if (is_integer(part1) && is_integer(part2))
				return true;
			else
				return false;
		} else
			return is_integer(s);
	}

	// check for valid date in format yyyy-mm-dd
	inline bool is_date(std::string_view value) 
	{
		if (value.length() != 10)
			return false;

		std::string sd {value.substr(8, 2)};
		if (!is_integer(sd)) return false;
		std::string sm {value.substr(5, 2)};
		if (!is_integer(sm)) return false;
		std::string sy {value.substr(0, 4)};
		if (!is_integer(sy)) return false;

		int d = std::stoi(sd);
		int m = std::stoi(sm);
		int y = std::stoi(sy);

		if (!(1 <= m && m <= 12) )
			return false;
		if (!(1 <= d && d <= 31) )
			return false;
		if ( d == 31 && (m == 2 || m == 4 || m == 6 || m == 9 || m == 11) )
			return false;
		if (d == 30 && m == 2)
			return false;
		if (m == 2 && d == 29) {
			if (y % 4 != 0 || y % 100 == 0) return false;
			if (y % 400 == 0 || y % 4 == 0) return true;
		}

		return true;
	}

	inline void replace_str(std::string &str, std::string_view from, std::string_view to) 
	{
		if (from.empty() || to.empty())
			return;
		size_t start_pos = 0;
		while((start_pos = str.find(from, start_pos)) != std::string::npos) {
			str.replace(start_pos, from.length(), to);
			start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
		}
	}	

	void save_blob(const std::string& filename, const std::string& content) noexcept 
	{
		std::ofstream ofs(filename, std::ios::binary);
		if ( ofs.is_open() )
			ofs << content;
		else 
			logger::log("http", "error", "save_blob() cannot write to file: " + filename, true);
	}

	//upload support functions---------
	std::vector<std::string_view> parse_body(auto req) {
		std::vector<std::string_view> vec;
		std::string_view body {req->payload};
		body = body.substr(req->bodyStartPos);
		const std::string delim{ "--" + req->boundary + "\r\n"};
		const std::string end_delim{"--" + req->boundary + "--" + "\r\n"};
		for (const auto& word : std::views::split(body, delim)) {
			auto part {std::string_view{word}};
			if (part.empty()) continue;
			if (part.ends_with(end_delim))
				part = part.substr(0, part.find(end_delim));
			vec.push_back(part);
		}
		return vec;
	}

	std::vector<std::string_view> parse_part(std::string_view body) {
		std::vector<std::string_view> vec;
		constexpr std::string_view delim{"\r\n"};
		for (const auto& word : std::views::split(body, delim)) {
			auto part {std::string_view{word}};
			if (part.empty()) continue;
			vec.push_back(part);
		}
		return vec;
	}

	std::string_view extract_attribute(std::string_view part, const std::string& name) {
		const std::string delim1 {name + "=\""};
		const std::string delim2 {"\""};
		if (auto pos1 {part.find(delim1)}; pos1 != std::string::npos) {
			pos1 += delim1.size();
			if (auto pos2 {part.find(delim2, pos1)}; pos2 != std::string::npos) 
				return part.substr(pos1, pos2 - pos1);
		}
		return "";    
	}

	std::string_view get_part_content_type(std::string_view line) {
		std::string_view marker {"Content-Type: "};
		auto pos = line.find(marker);
		pos += marker.size();
		return line.substr(pos);
	}

	http::form_field get_form_field(std::vector<std::string_view> part) {
		http::form_field f;
		size_t idx{1};
		f.name = extract_attribute(part[0], "name");
		f.filename = extract_attribute(part[0], "filename");
		if (!f.filename.empty()) {
			f.content_type = get_part_content_type(part[1]);
			idx = 2;
		}
		for (auto i = idx; i < part.size(); i++) {
			f.data.append(part[i]);
			if (!f.filename.empty())
				f.data.append("\r\n");
		}
		return f;
	}
	
	std::vector<http::form_field> parse_multipart(auto req) 
	{
		std::vector<http::form_field> fields;
		for (const auto& vec {parse_body(req)}; auto& part: vec) {
			auto elems {parse_part(part)};
			fields.push_back(get_form_field(elems));
		}
		return fields;
	}
	//--------------------------

	//mail and log support------
	std::string load_mail_template(const std::string& filename)
	{
		std::ifstream file(filename);
		if (std::stringstream buffer; file.is_open()) {
			buffer << file.rdbuf();
			return buffer.str();
		} else {
			throw http::resource_not_found_exception("mail body template not found: " + filename);
		}
	}

	std::string replace_params(auto req, std::string body)
	{
		if (std::size_t pos = body.find("$userlogin"); pos != std::string::npos)
			body.replace(pos, std::string("$userlogin").length(), req->user_info.login);
		if (req->input_rules.empty())
			return body;
		for (const auto& p:req->input_rules)
		{
			std::string name {"$" + p.get_name()};
			if (std::size_t pos = body.find(name); pos != std::string::npos) {
				const auto& value = req->params[p.get_name()];
				if (value.empty()) 
					body.replace(pos, name.length(), "");
				else
					body.replace(pos, name.length(), value);
			}
		}
		return body;
	}	

	std::string get_mail_body(auto req, const std::string& template_file)
	{
		std::string tpl_path {"/var/mail/" + template_file};
		return replace_params(req, load_mail_template(tpl_path));
	}
	//---------------------


}

namespace http
{
	std::string get_uuid() noexcept 
	{
		std::random_device r;
		std::default_random_engine eng{r()};
		std::uniform_int_distribution dist{0, 15};
		constexpr auto v {"0123456789abcdef"};
		constexpr std::array<bool, 16> dash { false, false, false, false, true, false, true, false, true, false, true, false, false, false, false, false };

		std::string res;
		for (const auto& c: dash) {
			if (c) res += "-";
			res += v[dist(eng)];
			res += v[dist(eng)];
		}
		return res;
	}

	std::string get_response_date() noexcept
	{
		std::array<char, 64> buf;
		auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		std::tm tm{};
		gmtime_r(&now, &tm);
		std::strftime(buf.data(), buf.size(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
		return std::string(buf.data());		
	}

	line_reader::line_reader(std::string_view str) : buffer{str} { }
	
	bool line_reader::eof() const noexcept { return _eof; }
	
	std::string_view line_reader::getline() {
		if (auto newpos = buffer.find(line_sep, pos); newpos != std::string::npos && newpos!= 0) {
			std::string_view line { buffer.substr( pos, newpos - pos ) };
			pos = newpos + line_sep.size();
			return line;
		} else {
			_eof = true;
			return "";
		}
	}

	response_stream::response_stream(int size) noexcept 
	{
		_buffer.reserve(size);
	}
	
	response_stream::response_stream() {
		_buffer.reserve(16383);
	}

	void response_stream::set_body(std::string_view body, std::string_view content_type, int max_age)
	{
		_buffer.append("HTTP/1.1 200 OK").append("\r\n");
		_buffer.append("Content-Length: ").append(std::to_string(body.size())).append("\r\n");
		_buffer.append("Content-Type: ").append(content_type).append("\r\n");
		_buffer.append("Date: ").append(get_response_date()).append("\r\n");
		_buffer.append("Keep-Alive: timeout=60, max=25\r\n");
		_buffer.append("Access-Control-Allow-Origin: " + _origin + "\r\n");
		_buffer.append("Access-Control-Expose-Headers: content-disposition\r\n");
		_buffer.append("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload;\r\n");
		_buffer.append("X-Frame-Options: SAMEORIGIN\r\n");
		if (max_age)
			_buffer.append("Cache-Control: max-age=").append(std::to_string(max_age)).append("\r\n");
		if (!_content_disposition.empty())
			_buffer.append("Content-Disposition: ").append(_content_disposition).append("\r\n");
		_buffer.append("\r\n").append(body);
	}
	
	void response_stream::set_content_disposition(std::string_view disposition)
	{
		_content_disposition = disposition;
	}
	
	void response_stream::set_origin(std::string_view origin)
	{
		_origin = origin;
	}
	
	response_stream& response_stream::operator <<(std::string_view data) {
		_buffer.append(data);
		return *this;
	}

	response_stream& response_stream::operator <<(const char* data) {
		_buffer.append(data);
		return *this;
	}

	response_stream& response_stream::operator <<(size_t data) {
		_buffer.append(std::to_string(data));
		return *this;
	}

	std::string_view response_stream::view() const noexcept {
		return std::string_view(_buffer);
	}
	
	size_t response_stream::size() const noexcept {
		return _buffer.size();
	}
	
	const char* response_stream::c_str() const noexcept {
		return _buffer.c_str();
	}
	
	void response_stream::append(const char* data, size_t len) noexcept
	{
		_buffer.append(data, len);
	}
	
	const char* response_stream::data() const noexcept {
		return _buffer.c_str();
	}
	
	void response_stream::clear() noexcept {
		_pos1 = 0;
		_buffer.clear();
		_content_disposition.clear();
		_origin.clear();
	}

	bool response_stream::write (int fd) noexcept 
	{
		const char* buf = data();
		buf += _pos1;
		const char* end = data() + size();
		ssize_t count = send(fd, buf, end - buf, MSG_NOSIGNAL);
		if (count > 0) {
			buf += count;
			_pos1 += count;
		}
		while (buf != end)
		{
			count = send(fd, buf, end - buf, MSG_NOSIGNAL);
			if (count > 0) {
				buf += count;
				_pos1 += count;
				continue;
			} else { 
				if (errno == EAGAIN)
					return false;
			}
			if (count <= 0 && errno != EAGAIN) {
				logger::log("epoll", "error", "send() error: $1 FD: $2", {std::string(strerror(errno)), std::to_string(fd)});
				return true;
			}
		}
		return true;
	}

	void request::clear() 
	{
		response.clear();
		payload.clear();
		headers.clear();
		params.clear();
		input_rules.clear();
		errcode = 0;
		errmsg = "";
		origin = "null";
		queryString = "";
		path = "";
		boundary = "";
		token = "";
		bodyStartPos = 0;
		contentLength = 0;
		method = "";
		isMultipart = false;
		user_info.login = "";
		user_info.mail = "";
		user_info.roles = "";
		user_info.exp = 0;
	}
	
	
	void request::enforce(verb v) const {
		const std::array<std::string, 2> methods {"GET", "POST"};
		if (method != methods[int(v)])
			throw method_not_allowed_exception(method);
	}
	
	void request::test_field(const http::input_rule& r, std::string& value)
	{
		using enum field_type;
		switch (r.get_type()) {
			case INTEGER:
				if (!is_integer(value))
					throw invalid_input_exception(r.get_name(), "err.invalidtype");
				break;
			case DOUBLE:
				if (!is_double(value))
					throw invalid_input_exception(r.get_name(), "err.invalidtype");
				break;
			case DATE:
				if (!is_date(value))
					throw invalid_input_exception(r.get_name(), "err.invalidtype");
				break;
			case STRING:
				//prevent sql injection
				replace_str(value, "'", "''");
				replace_str(value, "\\", "");
				break;
		}
	}
	
	//throws invalid_input_exception if any validation rule fails
	void request::enforce(const std::vector<input_rule>& rules)
	{
		input_rules = rules; //store in request for later use
		for (const auto& r: rules) 
		{
			if (r.get_required() && !params.contains(r.get_name())) 
				throw invalid_input_exception(r.get_name(), "err.required");
			auto& value = params[r.get_name()];
			value = trim(value);
			if (r.get_required() && value.empty())
				throw invalid_input_exception(r.get_name(), "err.required");
			if (!value.empty())
				test_field(r, value);
		}
	}

	void request::set_parse_error(std::string_view msg)
	{
		errcode = -1;
		errmsg  = msg;
	}

	bool request::parse_uri(line_reader& lr)
	{
		size_t nextpos{0};
		std::string_view line = lr.getline();
		if (auto newpos = line.find(" ", 0); newpos != std::string::npos) {
			method = line.substr( 0, newpos );
			nextpos = newpos;
		} else {
			set_parse_error(logger::format("Bad request -> 1st line lacks http method: $1", {line}));
			return false;
		}

		if (method != "GET" && method != "POST" && method != "OPTIONS") {
			set_parse_error(logger::format("Bad request -> only GET-POST-OPTIONS are supported: $1", {method}));
			return false;
		}

		if (auto newpos = line.find("/", nextpos); newpos != std::string::npos) {
			queryString = line.substr( newpos,  line.find(" ", newpos) - newpos );
		} else {
			set_parse_error(logger::format("Bad request -> 1st line lacks URI path: : $1", {line}));
			return false;
		}

		if (auto newpos = queryString.find("?", 0); newpos != std::string::npos) {
			path = queryString.substr( 0,  newpos );
		} else {
			path = queryString;
		}
		return true;
	}
	
	bool request::add_header(const std::string& header, const std::string& value)
	{
		auto [iter, success] {headers.try_emplace(header, value)};
		if (!success) {
			set_parse_error(logger::format("Bad request -> duplicated header $1", {header}));
			return false;
		}
		return true;
	}
	
	bool request::set_content_length(std::string_view value)
	{
		try {
			contentLength = std::stoul(value.data());
		} catch (const std::invalid_argument& e) {
			set_parse_error(logger::format("Bad request -> invalid content length header: $1 value: $1", {e.what(), value.data()}));
			return false;			
		} catch (const std::out_of_range& e) {
			set_parse_error(logger::format("Bad request -> invalid content length header - $1 value: $2", {e.what(), value.data()}));
			return false;			
		}
		return true;
	}
	
	std::pair<std::string, std::string> request::split_header_line(std::string_view line)
	{
		auto newpos = line.find(":", 0); 
		std::string header_name {lowercase(line.substr( 0,  newpos))};
		std::string header_value {line.substr(newpos + 2,  line.size() - newpos + 2)};
		return std::make_pair(header_name, header_value);
	}
	
	bool request::parse_read_boundary(std::string_view value) 
	{
		isMultipart = false;
		if (value.contains("=")) {
			isMultipart = true;
			boundary = value.substr(value.find("=") + 1);
			return true;
		} else {
			set_parse_error("Bad request -> invalid multipart value, cannot read boundary");
			return false;
		}
	}
	
	bool request::validate_header(std::string_view header, std::string_view value)
	{
		if (header == "content-length" && !set_content_length(value)) 
			return false;
					
		if (header == "content-type" && value.starts_with("multipart") && !parse_read_boundary(value)) 
			return false;
					
		if (header == "authorization" && value.starts_with("Bearer"))
			token = value.substr(value.find(" ") + 1);

		if (header == "x-forwarded-for")
			remote_ip = value;					

		if (header == "origin") 
			origin = value.empty() ? "null":  value;
	
		return true;
	}	
	
	bool request::parse_headers(line_reader& lr)
	{
		while (!lr.eof()) {
			std::string_view line {lr.getline()};
			if (line.size()==0) break;
			
			if (!line.contains(": ")) {
				set_parse_error("Bad request -> invalid header format, header lacks ':'");
				return false;
			}
			
			auto [header, value] {split_header_line(line)};
			if (!add_header(header, value))
				return false;
	
			if (!validate_header(header, value))
				return false;
		}
		return true;
	}
	
	void request::parse() 
	{
		std::string_view str{payload};
		bodyStartPos = str.find("\r\n\r\n", 0) + 4;
		line_reader lr(str.substr(0, bodyStartPos));
	
		if (bodyStartPos <= 4) {
			set_parse_error("Bad request -> no proper HTTP request found");
			return;
		}
	
		if (!parse_uri(lr))
			return;

		if (!parse_headers(lr))
			return;

		if (contentLength <= 0 && method == "POST") {
			set_parse_error(logger::format("Bad request -> invalid content length: $1", {std::to_string(contentLength)}));
			return;
		}

		if (method=="POST" && (!isMultipart || contentLength <= 0)) {
			set_parse_error("Bad request -> POST supported for multipart/form-data only with a valid content-length header");
			return;
		}

		if (method=="GET" && !queryString.empty() && queryString.contains("?"))
			parse_query_string(queryString);
		
		response.set_origin(origin);
	}
	
	void request::parse_form() 
	{
		auto fields = parse_multipart(this);
		bool _save {true};
		for (auto& f: fields) {
			if (f.filename.empty()) {
				params.try_emplace(f.name, f.data);
				if (f.name=="title" && f.data.empty())
					_save = false;
			} else {
				std::string file_uuid {get_uuid()};
				params.try_emplace( "document", file_uuid);
				params.try_emplace( "content_len", std::to_string( f.data.size() ) );
				params.try_emplace( "content_type", f.content_type);
				params.try_emplace( "filename", f.filename);
				if (_save)
					save_blob(blob_path + file_uuid, f.data);
			}
		}
	}
	
	bool request::eof() 
	{
		if ( (payload.size() - bodyStartPos) == contentLength ) {
			if (method == "POST") 
				parse_form();
			return true;
		}
		else
			return false;
	}
		
	std::string request::get_header(const std::string& name) const 
	{
		if (auto value = headers.find(name); value != headers.end()) 
			return value->second;
		else
			return "";
	}
	
	std::string request::get_param(const std::string& name) const 
	{
		if (auto value = params.find(name); value != params.end()) 
			return value->second;
		else
			return "";
	}

	//this was coded this way (while instead of for loop) to be compliant with Sonar rule cpp:S886
	std::string request::decode_param(std::string_view encoded_string) const noexcept
	{
		std::string decoded_string;
		auto it {std::begin(encoded_string)};
		auto end {std::end(encoded_string)};
		while (it != end) {
			if (*it == '%') {
				const char hex_char1 = *std::next(it, 1);
				const char hex_char2 = *std::next(it, 2);
				decoded_string += static_cast<char>(std::strtol(std::string({hex_char1, hex_char2}).c_str(), nullptr, 16));
				std::advance(it, 3);
			} else {
				decoded_string += *it;
				std::advance(it, 1);
			}
		}
		return decoded_string;
	}

	void request::parse_param(std::string_view param) noexcept 
	{
		if (auto pos {param.find("=")}; pos != std::string::npos) {
			std::string_view name {param.substr(0, pos)};
			std::string_view value {param.substr(pos + 1, param.size() - pos)};
			if (value.contains("%"))
				params.try_emplace(std::string{name}, decode_param(value));
			else
				params.try_emplace(std::string{name}, value);
		}		
	}

	void request::parse_query_string(std::string_view qs) noexcept 
	{
		auto pos {qs.find("?")};
		std::string_view query_string = qs.substr(pos + 1);
		constexpr std::string_view delim{"&"};
		for (const auto& word : std::views::split(query_string, delim)) {
			parse_param(std::string_view{word});
		}
	}

	std::string request::get_sql(std::string sql)
	{
		if (input_rules.empty())
			return sql;
		if (std::size_t pos = sql.find("$userlogin"); pos != std::string::npos)
			sql.replace(pos, std::string("$userlogin").length(), "'" + user_info.login + "'");
		for (const auto& p:input_rules)
		{
			std::string name {"$" + p.get_name()};
			const auto& value = params[p.get_name()];
			if (std::size_t pos = sql.find(name); pos != std::string::npos) {
				if (value.empty()) {
					sql.replace(pos, name.length(), "NULL");
					continue;
				}
				switch (p.get_type()) {
					case field_type::INTEGER:
					case field_type::DOUBLE:
						sql.replace(pos, name.length(), value);
						break;
					default:
						sql.replace(pos, name.length(), "'" + value + "'");
				}
			}
		}
		return sql;
	}
	
	void request::check_security(const std::vector<std::string>& roles)
	{
		if (token.empty())
			throw login_required_exception(remote_ip, "No JWT token in request headers");
		
		if (auto [is_valid, user]{jwt::is_valid(token)}; !is_valid) 
			throw login_required_exception(remote_ip, "JWT token is not valid");
		else
			user_info = user;
		
		if (!roles.empty()) {
			if (user_info.roles.empty())
				throw access_denied_exception(user_info.login, remote_ip, "User has no roles");
			for (const auto& r: roles)
				if (user_info.roles.find(r) != std::string::npos) return;
			throw access_denied_exception(user_info.login, remote_ip, "User roles are not authorized to execute this service: " + user_info.roles);
		}
	}

	void request::log(std::string_view source, std::string_view level, const std::string& msg) noexcept
	{
		logger::log(source, level, replace_params(this, msg), true, get_header("x-request-id"));
	}

	void request::send_mail(const std::string& to, const std::string& subject, const std::string& body) noexcept
	{
		send_mail(to, "", subject, body, "", "");
	}

	void request::send_mail(const std::string& to, const std::string& cc, const std::string& subject, const std::string& body) noexcept
	{
		send_mail(to, cc, subject, body, "", "");
	}

	void request::send_mail(const std::string& to, const std::string& cc, const std::string& subject, const std::string& body, 
		const std::string& attachment, const std::string& attachment_filename) noexcept
	{
		auto mail_body {get_mail_body(this, body)};
		auto x_request_id {get_header("x-request-id")};
		std::jthread task ([=]() {
			smtp::mail m(env::get_str("CPP_MAIL_SERVER"), env::get_str("CPP_MAIL_USER"), env::get_str("CPP_MAIL_PWD"));
			m.set_x_request_id(x_request_id);
			m.set_to(to);
			m.set_cc(cc);
			m.set_subject(subject);
			m.set_body(mail_body);
			if (!attachment.empty()) {
				std::string filepath {attachment.starts_with("/") ? attachment : "/var/blobs/" + attachment};
				if (!attachment_filename.empty())
					m.add_attachment(filepath, attachment_filename);
				else
					m.add_attachment(filepath);
			}
			m.send();
		});
		task.detach();
	}

}