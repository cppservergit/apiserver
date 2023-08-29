#include "httputils.h"

namespace
{
	/* utility functions */
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

	struct line_reader {
	  public:
		explicit line_reader(std::string_view str) : buffer{str} { }
		bool eof() const noexcept { return _eof; }
		std::string_view getline() {
			if (auto newpos = buffer.find(line_sep, pos); newpos != std::string::npos && newpos!= 0) {
				std::string_view line { buffer.substr( pos, newpos - pos ) };
				pos = newpos + line_sep.size();
				return line;
			} else {
				_eof = true;
				return "";
			}
		}
		
	  private:
		bool _eof{false};
		std::string_view buffer;
		int pos{0};
		const std::string line_sep{"\r\n"};
	};

	response_stream::response_stream(int size) noexcept 
	{
		_buffer.reserve(size);
	}
	
	response_stream::response_stream() {
		_buffer.reserve(16383);
	}

	void response_stream::set_body(const std::string& body, const std::string& content_type, int max_age)
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
			_buffer.append("Cache-Control: max-age=" + std::to_string(max_age) + "\r\n");
		if (!_content_disposition.empty())
			_buffer.append("Content-Disposition: " + _content_disposition + "\r\n");
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
				logger::log("epoll", "error", std::string(__FUNCTION__) + " send() error: " + std::string(strerror(errno)) + " FD: " + std::to_string(fd));
				return true;
			}
		}
		return true;
	}

	request::request(int epollfd, int fdes, const char* ip): epoll_fd{epollfd}, fd {fdes}, remote_ip {ip}
	{
		headers.reserve(10);
		params.reserve(10);
		payload.reserve(8191);
	}

	request::request() 
	{
		headers.reserve(10);
		params.reserve(10);
		payload.reserve(8191);
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
		const std::string methods[] {"GET", "POST"};
		if (method != methods[int(v)])
			throw method_not_allowed_exception(method);
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
			if (!value.empty()) {
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
		}
	}	
	
	void request::parse() 
	{
		std::string_view str{payload};
		bodyStartPos = str.find("\r\n\r\n") + 4;
		line_reader lr(str.substr(0, bodyStartPos));
	
		if (bodyStartPos <= 4) {
			errcode = -1; 
			errmsg.append("Bad request format");
			return;
		}
	
		size_t nextpos{0};
		std::string_view line = lr.getline();
		if (auto newpos = line.find(" ", 0); newpos != std::string::npos) {
			method = line.substr( 0, newpos );
			nextpos = newpos;
		} else {
			errcode = -1; 
			errmsg.append("Bad request -> 1st line lacks http method: ").append(line);
			return;
		}

		if (method != "GET" && method != "POST" && method != "OPTIONS") {
			errcode = -1; 
			errmsg.append("Bad request -> only GET-POST-OPTIONS are supported: ").append(method);
			return;
		}

		if (auto newpos = line.find("/", nextpos); newpos != std::string::npos) {
			queryString = line.substr( newpos,  line.find(" ", newpos) - newpos );
		} else {
			errcode = -1; 
			errmsg.append("Bad request -> 1st line lacks '/': ").append(line);
			return;
		}

		if (auto newpos = queryString.find("?", 0); newpos != std::string::npos) {
			path = queryString.substr( 0,  newpos );
		} else {
			path = queryString;
		}

		try {
			while (!lr.eof()) {
				std::string_view line = lr.getline();
				if (line.size()==0) break;
				if (auto newpos = line.find(":", 0); newpos != std::string::npos) {
					auto h = headers.emplace(lowercase( std::string(line.substr( 0,  newpos)) ), line.substr( newpos + 2,  line.size() - newpos + 2));
					if (!h.second) {
						errcode = -1; 
						errmsg = "Bad request -> duplicated header in request: " + h.first->first + " " + path;
					}
					if (h.first->first == "content-length")
						contentLength = std::stoul(h.first->second);
					else if (h.first->first == "content-type") {
						if ( h.first->second.starts_with("multipart") ) {
							isMultipart = true;
							boundary = h.first->second.substr( h.first->second.find("=") + 1 );
						}
					}
					else if (h.first->first == "authorization")
					{
						if ( h.first->second.starts_with("Bearer") ) {
							token = h.first->second.substr( h.first->second.find(" ") + 1 );
						}						
					}
					else if (h.first->first == "x-forwarded-for")
					{
						remote_ip = h.first->second;					
					}
					else if (h.first->first == "origin") {
						origin = h.first->second;
						origin = origin.empty() ? "null":  origin;
					}
				} else {
					errcode = -1; 
					errmsg = "Bad request -> header lacks ':'";
					return;
				}
			}
		} catch (const std::exception& e) {
			errcode = -1; errmsg = "Bad request -> runtime exception while parsing the headers: " + std::string(e.what());
			return;
		}
		if (method=="GET")
			parse_query_string(queryString);
		
		if (contentLength <= 0 && method == "POST") {
			errcode = -1; 
			errmsg = "Bad request -> invalid content length: " + std::to_string(contentLength);
		}
		response.set_origin(origin);
	}
	
	bool request::eof() 
	{
		if ( (payload.size() - bodyStartPos) == contentLength ) {
			
			if (method == "POST") {
				auto fields = parse_multipart();
				bool _save {true};
				for (auto& f: fields) {
					if (f.filename.empty()) {
						params.emplace(f.name, f.data);
						if (f.name=="title" && f.data.empty())
							_save = false;
					} else {
						std::string file_uuid {get_uuid()};
						params.emplace( "document", file_uuid);
						params.emplace( "content_len", std::to_string( f.data.size() ) );
						params.emplace( "content_type", f.content_type);
						params.emplace( "filename", f.filename);
						if (_save)
							save_blob(blob_path + file_uuid, f.data);
					}
				}
			}
		
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

	std::string_view request::get_cookie(std::string_view cookieHdr) 
	{
		const std::string token{"CPPSESSIONID="};
		if (auto pos = cookieHdr.find(token); pos!=std::string::npos) {
			std::string_view val1 = cookieHdr.substr( pos + token.size() );
			if (auto pos2 = val1.find(";"); pos2!=std::string::npos) {
				std::string_view val2 = val1.substr(0, pos2);
				return val2;
			} else 
				return val1;
		} else
			return "";
	}

	std::string request::lowercase(std::string s) noexcept 
	{
		std::transform( s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); } );
		return s;
	}	

	//using code taken from: https://gitlab.com/eidheim/Simple-Web-Server
	std::string request::decode_param(std::string_view value) const noexcept 
	{
		std::string result;
		result.reserve(63);
		for(std::size_t i = 0; i < value.size(); ++i) {
			auto &chr = value[i];
			if(chr == '%' && i + 2 < value.size()) {
				std::string hex{value.substr(i + 1, 2)};
				auto decoded_chr = static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
				result += decoded_chr;
				i += 2;
			}
			else if(chr == '+')
				result += ' ';
			else
				result += chr;
		}
		return result;
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
		if(qs.empty())
			return;

		if (auto pos = qs.find("?"); pos == std::string::npos)
			return;
		else {
			std::string_view query_string = qs.substr(pos + 1);
			constexpr std::string_view delim{"&"};
			for (const auto& word : std::views::split(query_string, delim)) {
				parse_param(std::string_view{word});
			}
		}
	}
	
	std::string request::get_part_content_type(std::string value) 
	{
		if (auto pos = value.find(": "); pos != std::string::npos) {
			value.erase(0, pos + 1);
			value.pop_back();
		}
		return value;
	}	
	
	std::pair<std::string, std::string> request::get_part_field(std::string value) 
	{
		
		std::string token_name{"name=\""};
		std::string token_filename{"filename=\""};
		std::string name = value;
		std::string filename = value;
		
		//Content-Disposition: form-data; name="file1"; filename="a.txt"
		if (auto pos = name.find(token_name); pos!=std::string::npos) {
			name.erase(0, pos + token_name.size());
			if (auto pos2 = name.find("\""); pos2!=std::string::npos)
				name.erase(pos2);
		} else
			name = "";

		if (auto pos = filename.find(token_filename); pos!=std::string::npos) {
			filename.erase(0, pos + token_filename.size());
			if (auto pos2 = filename.find("\""); pos2!=std::string::npos)
				filename.erase(pos2);
		} else
			filename = "";
		
		return std::pair<std::string, std::string>(name, filename);
		
	}

	std::vector<form_field> request::parse_multipart() 
	{
		std::string _boundary{ "--" + boundary };
		std::string endBoundary{_boundary + "--"};
		
		std::vector<form_field> fields;
		fields.reserve(5);
		
		std::string dataBuffer;
		dataBuffer.reserve(131071);
		std::pair<std::string, std::string> field;
		std::string s;
		std::istringstream is( payload.substr(bodyStartPos) );
		std::string contentType{""};
		
		while ( getline(is, s) ) {
			if (s.starts_with(_boundary)) //remove '\r'
				s.pop_back();
			if (s==_boundary) {
				if (!field.first.empty()) {
					if ( !field.second.empty() && dataBuffer.size() ) { 
						//trim extra \r\n in file fields
						dataBuffer.pop_back(); 
						dataBuffer.pop_back();
					}
					fields.emplace_back(field.first, field.second, contentType, dataBuffer);
					field.first = ""; field.second = ""; contentType=""; dataBuffer.clear();
				}
				getline(is, s); //read Content-Disposition
				field = get_part_field(s);
				if (!field.second.empty()) {
					getline(is, s); //content-type
					contentType = get_part_content_type(s);
				} else {
					contentType = "";
				}
				getline(is, s); //skip \r\n	
				continue;
			} else if (s==endBoundary) {
				if (!field.first.empty()) {
					if ( !field.second.empty() && dataBuffer.size() ) {
						//trim extra \r\n in file fields
						dataBuffer.pop_back(); 
						dataBuffer.pop_back();
					}
					fields.emplace_back(field.first, field.second, contentType, dataBuffer);
					field.first = ""; field.second = ""; contentType=""; dataBuffer.clear();
				}			
			} else {
				if (s.size() && s.back() == '\r' && field.second.empty())
					s.pop_back(); //remove '\r' if it is not a file field
				dataBuffer.append(s);
				if (!field.second.empty())
					dataBuffer.append("\n");
			}
		}
		return fields;
	}

	std::string request::get_sql(std::string sql)
	{
		if (input_rules.size() == 0)
			return sql;
		if (std::size_t pos = sql.find("$userlogin"); pos != std::string::npos)
			sql.replace(pos, std::string("$userlogin").length(), "'" + user_info.login + "'");
		for (const auto& p:input_rules)
		{
			std::string name {"$" + p.get_name()};
			auto& value = params[p.get_name()];
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
		
		if (roles.size()) {
			if (user_info.roles.empty())
				throw access_denied_exception(user_info.login, remote_ip, "User has no roles");
			for (const auto& r: roles)
				if (user_info.roles.find(r) != std::string::npos) return;
			throw access_denied_exception(user_info.login, remote_ip, "User roles are not authorized to execute this service: " + user_info.roles);
		}
	}

	std::string request::get_mail_body(const std::string& template_file)
	{
		std::string path {"/var/mail/" + template_file};
		std::stringstream buffer;
		{
			std::ifstream file(path);
			if (file.is_open())
				buffer << file.rdbuf();
			else {
				throw resource_not_found_exception("mail body template not found: " + path);
			}
		}
		std::string body {buffer.str()};
		if (std::size_t pos = body.find("$userlogin"); pos != std::string::npos)
			body.replace(pos, std::string("$userlogin").length(), user_info.login);
		if (input_rules.size() == 0)
			return body;
		for (const auto& p:input_rules)
		{
			std::string name {"$" + p.get_name()};
			if (std::size_t pos = body.find(name); pos != std::string::npos) {
				auto& value = params[p.get_name()];
				if (value.empty()) 
					body.replace(pos, name.length(), "");
				else
					body.replace(pos, name.length(), value);
			}
		}
		return body;
	}
	
	std::string request::replace_params(const std::string& template_file)
	{
		std::string body {template_file};
		if (std::size_t pos = body.find("$userlogin"); pos != std::string::npos)
			body.replace(pos, std::string("$userlogin").length(), user_info.login);
		if (input_rules.size() == 0)
			return body;
		for (const auto& p:input_rules)
		{
			std::string name {"$" + p.get_name()};
			if (std::size_t pos = body.find(name); pos != std::string::npos) {
				auto& value = params[p.get_name()];
				if (value.empty()) 
					body.replace(pos, name.length(), "");
				else
					body.replace(pos, name.length(), value);
			}
		}
		return body;
	}
	

}