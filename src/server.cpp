#include "server.h"

namespace
{
	constexpr char SERVER_VERSION[] = "API-Server++ v1.0.0";
	const std::string LOGGER_SRC {"server"};
	const int m_max_age {600};

	//describes api metadata
	struct webapi 
	{
		server::webapi_path path;
		std::string description;
		http::verb verb;
		std::vector<http::input_rule> rules;
		std::vector<std::string> roles;
		std::function<void(http::request&)> fn;
		bool is_secure {true};
		webapi(	const server::webapi_path& _path, 
				const std::string& _description,
				http::verb _verb,
				const std::vector<http::input_rule>& _rules,
				const std::vector<std::string>& _roles,
				std::function<void(http::request&)> _fn,
				bool _is_secure
			): path{_path}, description{_description}, verb{_verb}, rules{_rules}, roles{_roles}, fn{_fn}, is_secure{_is_secure}
		{ }
	};
	
	std::unordered_map<std::string, webapi> webapi_catalog;
		
	std::atomic<size_t> 	g_counter{0};
	std::atomic<double> 	g_total_time{0};
	std::atomic<int> 		g_active_threads{0};
	std::atomic<size_t> 	g_connections{0};

	inline void send_options(http::request& req);
	inline void send400(http::request& req);
	inline void send401(http::request& req);
	inline void send404(http::request& req);
	inline void send405(http::request& req);
	inline void sendRedirect(http::request& req, std::string newPath);
	
	void db_connect();
	void http_server(http::request& req) noexcept;
	
	int get_signalfd() noexcept;
	int get_listenfd(int port) noexcept;
	void start_epoll(int port) noexcept ;
	void consumer(std::stop_token tok) noexcept;
	bool read_request(http::request& req, const char* data, int bytes) noexcept;
	void print_server_info(const std::string& pod_name) noexcept;
	void prebuilt_services();

	struct worker_params {
		http::request& req;
	};
	
	std::queue<worker_params> m_queue;
	std::condition_variable m_cond;
	std::mutex m_mutex;
	int m_signal{get_signalfd()};

	inline void send_options(http::request& req)
	{
		std::string res = "HTTP/1.1 204 No Content\r\n"
		"Date: " + http::get_response_date() + "\r\n"
		"Access-Control-Allow-Origin: " + req.get_header("origin") + "\r\n"
		"Access-Control-Allow-Methods: GET, POST\r\n"
		"Access-Control-Allow-Headers: " + req.get_header("access-control-request-headers") + "\r\n"
		"Access-Control-Max-Age: 600\r\n"
		"Vary: Origin\r\n"
		"\r\n";
		req.response << res;
	}

	inline void send400(http::request& req) 
	{
		logger::log(LOGGER_SRC, "error", "bad http request - IP: " + req.remote_ip + " error: " + req.errmsg, true);
		std::string msg {"Bad request"};
		http::response_stream& res = req.response;
		res << "HTTP/1.1 400 Bad request" << "\r\n"
			<< "Content-Length: " << msg.size() << "\r\n"
			<< "Content-Type: " << "text/plain" << "\r\n" 
			<< "Keep-Alive: timeout=5, max=200" << "\r\n"
			<< "Date: " << http::get_response_date() << "\r\n"
			<< "Access-Control-Allow-Origin: " << req.origin << "\r\n"
			<< "Access-Control-Allow-Credentials: true" << "\r\n"
			<< "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload;" << "\r\n"
			<< "X-Frame-Options: SAMEORIGIN" << "\r\n"
			<< "\r\n"					
			<< msg;
	}

	inline void send401(http::request& req) 
	{
		std::string msg {"Please login with valid credentials"};
		http::response_stream& res = req.response;
		res << "HTTP/1.1 401 Unauthorized" << "\r\n"
			<< "Content-Length: " << msg.size() << "\r\n"
			<< "Content-Type: " << "text/plain" << "\r\n" 
			<< "Keep-Alive: timeout=5, max=200" << "\r\n"
			<< "Date: " << http::get_response_date() << "\r\n"
			<< "Access-Control-Allow-Origin: " << req.origin << "\r\n"
			<< "Access-Control-Allow-Credentials: true" << "\r\n"
			<< "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload;" << "\r\n"
			<< "X-Frame-Options: SAMEORIGIN" << "\r\n"
			<< "\r\n"					
			<< msg;
	}

	inline void send405(http::request& req) 
	{
		std::string msg {"Method not allowed"};
		http::response_stream& res = req.response;
		res << "HTTP/1.1 405 Method not allowed" << "\r\n"
			<< "Content-Length: " << msg.size() << "\r\n"
			<< "Content-Type: " << "text/plain" << "\r\n" 
			<< "Keep-Alive: timeout=5, max=200" << "\r\n"
			<< "Date: " << http::get_response_date() << "\r\n"
			<< "Access-Control-Allow-Origin: " << req.origin << "\r\n"
			<< "Access-Control-Allow-Credentials: true" << "\r\n"
			<< "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload;" << "\r\n"
			<< "X-Frame-Options: SAMEORIGIN" << "\r\n"
			<< "\r\n"					
			<< msg;
	}
	
	inline void send404(http::request& req) {
		
		std::string msg {"Resource not found"};
		http::response_stream& res = req.response;
		res << "HTTP/1.1 404 Not found" << "\r\n"
			<< "Content-Length: " << msg.size() << "\r\n"
			<< "Content-Type: " << "text/plain" << "\r\n" 
			<< "Keep-Alive: timeout=5, max=200" << "\r\n"
			<< "Date: " << http::get_response_date() << "\r\n"
			<< "Access-Control-Allow-Origin: " << req.origin << "\r\n"
			<< "Access-Control-Allow-Credentials: true" << "\r\n"
			<< "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload;" << "\r\n"
			<< "X-Frame-Options: SAMEORIGIN" << "\r\n"
			<< "\r\n"					
			<< msg;

	}

	inline void sendRedirect(http::request& req, std::string newPath) {
		std::string msg {"301 Moved permanently"};
		http::response_stream& res = req.response;
		res << "HTTP/1.1 301 Moved permanently" << "\r\n"
			<< "Location: " << newPath << "\r\n" 
			<< "Keep-Alive: timeout=5, max=200" << "\r\n"
			<< "Content-Length: " << msg.size() << "\r\n"
			<< "Content-Type: " << "text/plain" << "\r\n" 
			<< "Date: " << http::get_response_date() << "\r\n"
			<< "Access-Control-Allow-Origin: " << req.origin << "\r\n"
			<< "Access-Control-Allow-Credentials: true" << "\r\n"
			<< "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload;" << "\r\n"
			<< "X-Frame-Options: SAMEORIGIN" << "\r\n"
			<<  "\r\n"
			<< msg;
	}
	
	void db_connect()
	{
		int i{0};
		while (true)
		{
			++i;
			std::string dbname {"DB" + std::to_string(i)};
			std::string connstr{env::get_str(dbname)};
			if (!connstr.empty()) 
				sql::connect(dbname, connstr);
			else
				break;
		}
	}

	void http_server(http::request& req) noexcept
	{
		++g_active_threads;	

		logger::set_request_id(req.get_header("x-request-id"));
		jwt::clear();

		auto start = std::chrono::high_resolution_clock::now();

		if (!req.errcode) {
			try {
				if (req.method == "OPTIONS") //preflight request
					send_options(req);
				else {
					if (auto obj = webapi_catalog.find(req.path); obj != webapi_catalog.end()) 
					{
						req.enforce(obj->second.verb);
						if (obj->second.rules.size())
							req.enforce(obj->second.rules);
						if (obj->second.is_secure)
							req.check_security(obj->second.roles);
						obj->second.fn(req); //run lambda service
					}
					else
						throw http::resource_not_found_exception(req.path);
				}
			} catch (const http::invalid_input_exception& e) { //thrown by request::enforce()
				logger::log("service", "error", req.path + " " + e.what(), true);
				std::string error {R"({"status": "INVALID", "validation": {"id": "$1", "description": "$2"}})"};
				error.replace(error.find("$1"), 2, e.get_field_name());
				error.replace(error.find("$2"), 2, e.get_error_description());
				req.response.set_body(error);
			} catch (const http::access_denied_exception& e) { //thrown by request::check_security()
				logger::log("security", "error", req.path + " " + e.what(), true);
				std::string error {R"({"status": "INVALID", "validation": {"id": "_dialog_", "description": "$err.accessdenied"}})"};
				req.response.set_body(error);
			} catch (const http::login_required_exception& e) { //thrown by request::check_security()
				logger::log("security", "error", req.path + " " + e.what(), true);
				send401(req);
			} catch (const http::resource_not_found_exception& e) { //may be thrown by lambda service
				logger::log("service", "error", req.path + " " + e.what(), true);
				send404(req);
			} catch (const http::method_not_allowed_exception& e) { //thrown by request::enforce(verb)
				logger::log("security", "error", req.path + " " + e.what(), true);
				send405(req);
			} catch (const std::exception& e) { //thrown by sql:: functions
				logger::log("service", "error", req.path + " " + std::string(e.what()), true);
				req.response.set_body(R"({"status": "ERROR", "description": "Service error"})");
			}
		} else
			send400(req);
		
		auto finish = std::chrono::high_resolution_clock::now();
		std::chrono::duration <double>elapsed = finish - start;				

		if (env::http_log_enabled())
			logger::log("access-log", "info", "fd=" + std::to_string(req.fd) 
				+ " remote-ip=" + req.remote_ip + " "
				+ req.method
				+ " path=" + req.path 
				+ " elapsed-time=" + std::to_string(elapsed.count()) 
				+ " user=" + jwt::user_get_login(), true);

		g_total_time += elapsed.count();
		++g_counter;
		--g_active_threads;
	}

	inline bool read_request(http::request& req, const char* data, int bytes) noexcept
	{
		bool first_packet { (req.payload.size() > 0) ? false : true };
		req.payload.append(data, bytes);
		if (first_packet) {
			req.parse();
			if (req.method == "GET" || req.errcode ==  -1)
				return true;
		}
		if (req.eof())
			return true;
		return false;
	}

	inline int get_signalfd() noexcept 
	{
		signal(SIGPIPE, SIG_IGN);
		sigset_t sigset;
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGINT);
		sigaddset(&sigset, SIGTERM);
		sigaddset(&sigset, SIGQUIT);
		sigprocmask(SIG_BLOCK, &sigset, NULL);
		int sfd { signalfd(-1, &sigset, 0) };
		logger::log("signal", "info", "signal interceptor registered");
		return sfd;
	}

	inline int get_listenfd(int port) noexcept 
	{
		int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		int on = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_port = htons(port);
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htons(INADDR_ANY);
		
		int rc = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
		if (rc == -1) {
			logger::log("epoll", "error", "bind() failed  port: " + std::to_string(port) + " " + std::string(strerror(errno)));
			exit(-1);
		}
		logger::log("epoll", "info", "listen socket FD: " + std::to_string(fd) + " port: " + std::to_string(port));
		return fd;
	}

	void consumer(std::stop_token tok) noexcept 
	{
		logger::log("pool", "info", "starting worker thread", true);
		db_connect(); //establish database connection for this thread
		
		while(!tok.stop_requested())
		{
			//prepare lock
			std::unique_lock lock{m_mutex}; 
			//release lock, reaquire it if conditions met
			m_cond.wait(lock, [&tok] { return (!m_queue.empty() || tok.stop_requested()); }); 
			
			//stop requested?
			if (tok.stop_requested()) { lock.unlock(); break; }
			
			//get task
			auto params = m_queue.front();
			m_queue.pop();
			lock.unlock();
			
			//---processing task (run microservice)
			http_server(params.req);
			
			//request ready, set epoll fd for output
			#ifdef DEBUG
				logger::log("epoll", "DEBUG", "task finished, consumer thread setting epoll mode to epollout FD: " + std::to_string(params.req.fd), true);
			#endif			
			epoll_event event;
			event.events = EPOLLOUT | EPOLLET | EPOLLRDHUP;
			event.data.ptr = &params.req;
			epoll_ctl(params.req.epoll_fd, EPOLL_CTL_MOD, params.req.fd, &event);
		}
		
		//ending task - free resources
		logger::log("pool", "info", "stopping worker thread", true);
	}

	void start_epoll(int port) noexcept 
	{
		int epoll_fd {epoll_create1(0)};
		logger::log("epoll", "info", "starting epoll FD: " + std::to_string(epoll_fd));

		int listen_fd {get_listenfd(port)};
		listen(listen_fd, SOMAXCONN);
		
		epoll_event event_listen;
		event_listen.data.fd = listen_fd;
		event_listen.events = EPOLLIN;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event_listen);
		  
		epoll_event event_signal;
		event_signal.data.fd = m_signal;
		event_signal.events = EPOLLIN;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, m_signal, &event_signal);

		std::unordered_map<int, http::request> buffers;
		std::array<char, 8192> data{};
		const int MAXEVENTS = 64;
		epoll_event events[MAXEVENTS];
		bool exit_loop {false};
		while (true)
		{
			int n_events = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
			for (int i = 0; i < n_events; i++)
			{
				if (((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP) || events[i].events & EPOLLERR))
				{
					if (events[i].data.ptr == NULL) {
						logger::log("epoll", "error", "epoll data ptr is null - unable to retrieve request object");
						continue;
					}
					http::request& req = *static_cast<http::request*>(events[i].data.ptr);
					req.clear();
					int fd {req.fd};			
					#ifdef DEBUG
						std::stringstream ss;
						ss << &req;
						logger::log("epoll", "DEBUG", "retrieved http::request (" + ss.str() + ") - FD: " + std::to_string(fd));
					#endif
					int rc = close(fd);
					--g_connections;
					if (rc == -1)
						logger::log("epoll", "error", "close FAILED for FD: " + std::to_string(fd) + " " + std::string(strerror(errno)));
					#ifdef DEBUG
						logger::log("epoll", "DEBUG", "close FD: " + std::to_string(fd));
					#endif
				}
				else if (m_signal == events[i].data.fd) //shutdown
				{
					logger::log("signal", "info", "stop signal received for epoll FD: " + std::to_string(epoll_fd) + " SFD: " + std::to_string(m_signal));
					exit_loop = true;
					break;
				}
				else if (listen_fd == events[i].data.fd) // new connection.
				{
					struct sockaddr addr;
					socklen_t len;
					len = sizeof addr;
					int fd { accept4(listen_fd, &addr, &len, SOCK_NONBLOCK) };
					if (fd == -1) {
						logger::log("epoll", "error", "connection accept FAILED for epoll FD: " + std::to_string(epoll_fd) + " " + std::string(strerror(errno)));
						continue;
					}
					++g_connections;
					const char* remote_ip = inet_ntoa(((struct sockaddr_in*)&addr)->sin_addr);
					
					#ifdef DEBUG
						auto start = std::chrono::high_resolution_clock::now();
					#endif
					
					//store pointer to request object
					epoll_event event;
					if (buffers.contains(fd)) {
						http::request& req {buffers[fd]};
						req.remote_ip = std::string(remote_ip);
						req.fd = fd;
						req.epoll_fd = epoll_fd;
						event.data.ptr = &req;
					} else {
						auto& pair = *buffers.emplace(fd, http::request(epoll_fd, fd, remote_ip)).first;
						event.data.ptr = &pair.second;
					}
					event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
					epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
					
					#ifdef DEBUG
						auto finish = std::chrono::high_resolution_clock::now();
						std::chrono::duration <double>elapsed = finish - start;	
						logger::log("epoll", "DEBUG", "get request PTR FD: " + std::to_string(fd) + " duration: " +  std::to_string(elapsed.count()), true);
					#endif
					
					#ifdef DEBUG
						std::stringstream ss;
						ss <<  &pair.second;
						logger::log("epoll", "DEBUG", "stored pointer to http::request (" + ss.str() + ") - FD: " + std::to_string(fd));
						logger::log("epoll", "DEBUG", "accept FD: " + std::to_string(fd));
					#endif				
				}
				else // read/write
				{
					if (events[i].data.ptr == NULL) {
						logger::log("epoll", "error", "epoll data ptr is null - unable to retrieve request object");
						continue;
					}
					http::request& req = *static_cast<http::request*>(events[i].data.ptr);
					int fd {req.fd};
					#ifdef DEBUG
						std::stringstream ss;
						ss << &req;
						logger::log("epoll", "DEBUG", "retrieved http::request (" + ss.str() + ") - FD: " + std::to_string(fd));
					#endif
					
					if (events[i].events & EPOLLIN) {
						#ifdef DEBUG
							logger::log("epoll", "DEBUG", "epollin FD: " + std::to_string(fd));
						#endif				
						bool run_task {false};
						while (true) 
						{
							int count = read(fd, data.data(), data.size());
							#ifdef DEBUG
								logger::log("epoll", "DEBUG", "read " + std::to_string(count) + " bytes FD: " + std::to_string(fd));
							#endif							
							if (count == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
								break;
							}
							if (count > 0) {
								if (read_request(req, data.data(), count)) {
									run_task = true;
									break;
								}
							}
							else {
								logger::log("epoll", "error", "read error FD: " + std::to_string(fd) + " " + std::string(strerror(errno)));
								req.clear();
								break;
							}
						}
						if (run_task) {
							#ifdef DEBUG
								logger::log("epoll", "DEBUG", "dispatching task FD: " + std::to_string(fd));
							#endif
							//producer
							worker_params wp {req};
							{
								std::scoped_lock lock {m_mutex};
								m_queue.push(wp);
							}
							m_cond.notify_all();
						}
					} else if (events[i].events & EPOLLOUT) {
						#ifdef DEBUG
							logger::log("epoll", "DEBUG", "epollout FD: " + std::to_string(fd));
						#endif				
						//send response
						if (req.response.write(fd)) {
							req.clear();
							#ifdef DEBUG
								logger::log("epoll", "DEBUG", "write complete, setting mode to epollin FD: " + std::to_string(fd));
							#endif							
							epoll_event event;
							event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
							event.data.ptr = &req;
							epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
						}
					}
				}
			}
			if (exit_loop)
				break;
		}

		close(listen_fd);
		logger::log("epoll", "info", "closing listen socket FD: " + std::to_string(listen_fd));
		close(epoll_fd);
		logger::log("epoll", "info", "closing epoll FD: " + std::to_string(epoll_fd));
	}

	void print_server_info(const std::string& pod_name) noexcept 
	{
		logger::log("env", "info", "port: " + std::to_string(env::port()));
		logger::log("env", "info", "pool size: " + std::to_string(env::pool_size()));
		logger::log("env", "info", "login log: " + std::to_string(env::login_log_enabled()));
		logger::log("env", "info", "http log: " + std::to_string(env::http_log_enabled()));
		
		std::string msg1; msg1.reserve(255);
		std::string msg2; msg1.reserve(255);
		msg1.append("Pod: " + pod_name).append(" PID: ").append(std::to_string(getpid())).append(" starting ").append(SERVER_VERSION).append("-").append(std::to_string(CPP_BUILD_DATE));
		msg2.append("hardware threads: ").append(std::to_string(std::thread::hardware_concurrency())).append(" GCC: ").append(__VERSION__);
		logger::log("server", "info", msg1);
		logger::log("server", "info", msg2);
	}

	void prebuilt_services()
	{
		logger::log("server", "info", "registering built-in diagnostic and security services...");
		
		server::register_webapi
		(
			server::webapi_path("/api/ping"), 
			"Healthcheck service for Ingress and Load Balancer",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[](http::request& req) 
			{
				req.response.set_body( "{\"status\": \"OK\"}" );
			},
			false /* no security */
		);
				
		server::register_webapi
		(
			server::webapi_path("/api/version"), 
			"Get API-Server version and build date",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[](http::request& req) 
			{
				std::string json;
				std::array<char, 128> hostname{0};
				gethostname(hostname.data(), hostname.size());
				json.append("{\"status\": \"OK\", \"data\":[{\"pod\": \"").append(hostname.data()).append("\", ");
				json.append("\"server\": \"").append(SERVER_VERSION).append("-").append(std::to_string(CPP_BUILD_DATE)).append("\"}]}");
				req.response.set_body(json);
			},
			false /* no security */
		);

		server::register_webapi
		(
			server::webapi_path("/api/sysinfo"), 
			"Return global system diagnostics",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[](http::request& req) 
			{
				std::string json;
				std::array<char, 128> hostname{0};
				gethostname(hostname.data(), hostname.size());
				const double avg{ ( g_counter > 0 ) ? g_total_time / g_counter : 0 };
				std::array<char, 64> str1{0}; std::to_chars(str1.data(), str1.data() + str1.size(), g_counter);
				std::array<char, 64> str2{0}; std::to_chars(str2.data(), str2.data() + str2.size(), avg, std::chars_format::fixed, 8);
				std::array<char, 64> str3{0}; std::to_chars(str3.data(), str3.data() + str3.size(), g_connections);
				std::array<char, 64> str4{0}; std::to_chars(str4.data(), str4.data() + str4.size(), g_active_threads);
				json.append("{\"status\": \"OK\", \"data\":[{\"pod\":\"").append(hostname.data()).append("\",");
				json.append("\"totalRequests\":").append(str1.data()).append(",");
				json.append("\"avgTimePerRequest\":").append(str2.data()).append(",");
				json.append("\"connections\":").append(str3.data()).append(",");
				json.append("\"activeThreads\":").append(str4.data()).append("}]}");
				req.response.set_body(json);
			},
			false /* no security */
		);
		
		server::register_webapi
		(
			server::webapi_path("/api/metrics"), 
			"Return metrics in Prometheus format",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[](http::request& req) 
			{
				std::string body;
				std::array<char, 128> hostname{0};
				gethostname(hostname.data(), hostname.size());
				const double avg{ ( g_counter > 0 ) ? g_total_time / g_counter : 0 };
				std::array<char, 64> str1{0}; std::to_chars(str1.data(), str1.data() + str1.size(), g_counter);
				std::array<char, 64> str2{0}; std::to_chars(str2.data(), str2.data() + str2.size(), avg, std::chars_format::fixed, 8);
				std::array<char, 64> str3{0}; std::to_chars(str3.data(), str3.data() + str3.size(), g_connections);
				std::array<char, 64> str4{0}; std::to_chars(str4.data(), str4.data() + str4.size(), g_active_threads);

				body.append("# HELP cpp_requests_total The number of HTTP requests processed by this container.\n");
				body.append("# TYPE cpp_requests_total counter\n");
				body.append("cpp_requests_total{pod=\"").append(hostname.data()).append("\"} ").append(str1.data()).append("\n");

				body.append("# HELP cpp_connections Client tcp-ip connections.\n");
				body.append("# TYPE cpp_connections counter\n");
				body.append("cpp_connections{pod=\"").append(hostname.data()).append("\"} ").append(str3.data()).append("\n");

				body.append("# HELP cpp_active_threads Active threads.\n");
				body.append("# TYPE cpp_active_threads counter\n");
				body.append("cpp_active_threads{pod=\"").append(hostname.data()).append("\"} ").append(str4.data()).append("\n");

				body.append("# HELP cpp_avg_time Average request processing time in milliseconds.\n");
				body.append("# TYPE cpp_avg_time counter\n");
				body.append("cpp_avg_time{pod=\"").append(hostname.data()).append("\"} ").append(str2.data()).append("\n");

				req.response.set_body(body, "text/plain; version=0.0.4");
			},
			false /* no security */
		);

		server::register_webapi
		(
			server::webapi_path("/api/login"), 
			"Return metrics in Prometheus format",
			http::verb::POST, 
			{
				{"login", http::field_type::STRING, true},
				{"password", http::field_type::STRING, true}
			},
			{} /* roles */,
			[](http::request& req) 
			{
				std::string login{req.get_param("login")};
				std::string password{req.get_param("password")};
				if (login::bind(login, password)) {
					//return JWT token according to: https://openid.net/specs/openid-connect-core-1_0.html section 3.1.3.3
					std::string token {jwt::get_token(login, login::get_email(), login::get_roles())};
					std::string login_ok {"{\"status\":\"OK\",\"data\":[{\"displayname\":\"" + login::get_display_name() + "\"," + 
					"\"token_type\":\"bearer\",\"id_token\":\"" + token + "\"}]}"};
					req.response.set_body(login_ok);
					if (env::login_log_enabled())
						logger::log("security", "info", "login OK - user: " + login 
						+ " IP: " + req.remote_ip 
						+ " token: " + token 
						+ " roles: " + login::get_roles(), true);
				} else {
					logger::log("security", "warn", "login failed - user: " + login + " IP: " + req.remote_ip, true);
					std::string invalid_login = R"({"status": "INVALID", "validation": {"id": "login", "description": "$err.invalidcredentials"}})";
					req.response.set_body(invalid_login);
				}
			},
			false /* no security */
		);
	}
}

namespace server
{
	void register_webapi(
				const webapi_path& _path, 
				const std::string& _description,
				http::verb _verb,
				const std::vector<http::input_rule>& _rules,
				const std::vector<std::string>& _roles,
				std::function<void(http::request&)> _fn,
				bool _is_secure
				)
	{
		webapi_catalog.insert_or_assign
		(
			_path.get_path(),
			webapi
				( 
					_path, 
					_description,
					_verb,
					_rules,
					_roles,
					_fn,
					_is_secure
				)
		);
		std::string msg {_is_secure ? " " : " (insecure) "};
		logger::log("server", "info", "registered" + msg + "WebAPI for path: " + _path.get_path());
	}

	void start() noexcept
	{
		prebuilt_services();
		
		std::array<char, 128> hostname{0};
		gethostname(hostname.data(), hostname.size());
		std::string pod_name(hostname.data());

		print_server_info(pod_name);

		const auto pool_size {env::pool_size()};
		const auto port {env::port()};

		//create workers pool - consumers
		std::vector<std::stop_source> stops(pool_size);
		std::vector<std::jthread> pool(pool_size);
		for (int i = 0; i < pool_size; i++) {
			stops[i] = std::stop_source();
			pool[i] = std::jthread(consumer, stops[i].get_token());
		}
		
		start_epoll(port);

		logger::log("server", "info", pod_name + " shutting down...");
		
		//shutdown workers
		for (const auto& s: stops) {
			s.request_stop();
			m_cond.notify_all();
		}
		
		for (auto& t:pool)
			t.join();
	}
}