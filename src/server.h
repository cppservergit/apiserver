/*
 * server - epoll single-thread, workers-pool server
 *
 *  Created on: July 18, 2023
 *      Author: Martin Cordova cppserver@martincordova.com - https://cppserver.com
 *      Disclaimer: some parts of this library may have been taken from sample code publicly available
 *		and written by third parties. Free to use in commercial projects, no warranties and no responsabilities assumed 
 *		by the author, use at your own risk. By using this code you accept the forementioned conditions.
 */
#ifndef SERVER_H_
#define SERVER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/signalfd.h>
#include <netinet/tcp.h>
#include <iomanip>
#include <cstring> 
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <stop_token>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <charconv>
#include <functional>
#include <filesystem>
#include "util.h"
#include "env.h"
#include "logger.h"
#include "login.h"
#include "sql.h"
#include "httputils.h"
#include "jwt.h"
#include "email.h"

constexpr char SERVER_VERSION[] = "API-Server++ v1.0.3";
constexpr const char* LOGGER_SRC {"server"};

struct webapi_path
{
	public:
		consteval explicit webapi_path(std::string_view _path): m_path{_path} 
		{
			if (_path.contains(" ")) {
				throw std::string("Invalid WebAPI path -> contains space");
			}
			if (!_path.starts_with("/")) {
				throw std::string("Invalid WebAPI path -> must start with '/'");
			}
			if (_path.ends_with("/")) {
				throw std::string("Invalid WebAPI path -> cannot end with '/'");
			}
			std::string_view valid_chars{"abcdefghijklmnopqrstuvwxyz_-0123456789/"};
			for(const char& c: _path)
				if (!valid_chars.contains(c))
					throw std::string("Invalid WebAPI path -> contains an invalid character");
		}
		
	std::string get() const noexcept
	{
		return std::string(m_path);
	}

	private: 
		std::string_view m_path;
};


auto consumer = [](std::stop_token tok, auto srv) noexcept 
{
	logger::log("pool", "info", "starting worker thread", true);
	
	while(!tok.stop_requested())
	{
		//prepare lock
		std::unique_lock lock{srv->m_mutex}; 
		
		//release lock, reaquire it if conditions met
		srv->m_cond.wait(lock, [&tok, &srv]() { return (!srv->m_queue.empty() || tok.stop_requested()); }); 
		
		//stop requested?
		if (tok.stop_requested()) { lock.unlock(); break; }
		
		//get task
		auto params = srv->m_queue.front();
		srv->m_queue.pop();
		lock.unlock();
		
		//---run task
		srv->http_server(params.req, params.api);
		
		epoll_event event;
		event.events = EPOLLOUT | EPOLLET | EPOLLRDHUP;
		event.data.ptr = &params.req;
		epoll_ctl(params.req.epoll_fd, EPOLL_CTL_MOD, params.req.fd, &event);
	}
	sql::close_all();
	
	//ending task - free resources
	logger::log("pool", "info", "stopping worker thread", true);
};	

struct server
{
	struct webapi 
	{
		std::string description;
		http::verb verb;
		std::vector<http::input_rule> rules;
		std::vector<std::string> roles;
		std::function<void(http::request&)> fn;
		bool is_secure {true};
		webapi(	
				const std::string& _description,
				http::verb _verb,
				const std::vector<http::input_rule>& _rules,
				const std::vector<std::string>& _roles,
				const std::function<void(http::request&)>& _fn,
				bool _is_secure
			): description{_description}, verb{_verb}, rules{_rules}, roles{_roles}, fn{_fn}, is_secure{_is_secure}
		{ }
	};
	
	std::unordered_map<std::string, webapi, util::string_hash, std::equal_to<>> webapi_catalog;
		
	std::atomic<size_t> g_counter{0};
	std::atomic<double> g_total_time{0};
	std::atomic<int>	g_active_threads{0};
	std::atomic<size_t> g_connections{0};

	struct worker_params {
		http::request& req;
		const webapi& api;
	};

	std::queue<worker_params> m_queue;
	std::condition_variable m_cond;
	std::mutex m_mutex;
	int m_signal {get_signalfd()};

	void send_options(http::request& req)
	{
		std::string res {"HTTP/1.1 204 No Content\r\n"
		"Date: " + http::get_response_date() + "\r\n"
		"Access-Control-Allow-Origin: " + req.get_header("origin") + "\r\n"
		"Access-Control-Allow-Methods: GET, POST\r\n"
		"Access-Control-Allow-Headers: " + req.get_header("access-control-request-headers") + "\r\n"
		"Access-Control-Max-Age: 600\r\n"
		"Vary: Origin\r\n"
		"\r\n"};
		req.response << res;
	}

	void send400(http::request& req) 
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

	void send401(http::request& req) 
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

	void send405(http::request& req) 
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
	
	void send404(http::request& req) {
		
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

	void sendRedirect(http::request& req, const std::string& newPath) {
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

	void execute_service(http::request& req, const webapi& api)
	{
		req.enforce(api.verb);
		if (!api.rules.empty())
			req.enforce(api.rules);
		if (api.is_secure)
			req.check_security(api.roles);
		api.fn(req);
	}

	void process_request(http::request& req, const webapi& api) noexcept
	{
		std::string error_msg;
		try {
			if (req.method == "OPTIONS") //preflight request
				send_options(req);
			else 
				execute_service(req, api); //run lambda
		} catch (const http::invalid_input_exception& e) { 
			error_msg = e.what();
			req.response.set_body(logger::format(R"({"status": "INVALID", "validation": {"id": "$1", "description": "$2"}})", {e.get_field_name(), e.get_error_description()}));
		} catch (const http::access_denied_exception& e) { 
			error_msg = e.what();
			req.response.set_body(logger::format(R"({"status": "INVALID", "validation": {"id": "$1", "description": "$2"}})", {"_dialog_", "err.accessdenied"}));
		} catch (const http::login_required_exception& e) { 
			error_msg = e.what();
			send401(req);
		} catch (const http::resource_not_found_exception& e) { 
			error_msg = e.what();
			send404(req);
		} catch (const http::method_not_allowed_exception& e) { 
			error_msg = e.what();
			send405(req);
		} catch (const sql::database_exception& e) { 
			error_msg = e.what();
			req.response.set_body(R"({"status": "ERROR", "description": "Service error"})");
		}
		if (!error_msg.empty())
			logger::log("service", "error", "$1, $2", {req.path, error_msg}, true);
	}

	void log_request(const http::request& req, double duration) noexcept
	{
		std::string msg {"fd=$1 remote-ip=$2 $3 path=$4 elapsed-time=$5 user=$6"};
		logger::log("access-log", "info", msg, {std::to_string(req.fd), req.remote_ip, req.method, req.path, std::to_string(duration), req.user_info.login}, true);
	}

	void http_server (http::request& req, const webapi& api) noexcept
	{
		++g_active_threads;	

		auto start = std::chrono::high_resolution_clock::now();

		if (!req.errcode) {
			process_request(req, api);
		} else
			send400(req);
		
		auto finish = std::chrono::high_resolution_clock::now();
		std::chrono::duration <double>elapsed = finish - start;				

		if (env::http_log_enabled())
			log_request(req, elapsed.count());

		g_total_time += elapsed.count();
		++g_counter;
		--g_active_threads;
	};

	bool read_request(http::request& req, const char* data, int bytes) noexcept
	{
		bool first_packet { (req.payload.empty()) ? true : false };
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

	int get_signalfd() noexcept 
	{
		signal(SIGPIPE, SIG_IGN);
		sigset_t sigset;
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGINT);
		sigaddset(&sigset, SIGTERM);
		sigaddset(&sigset, SIGQUIT);
		sigprocmask(SIG_BLOCK, &sigset, nullptr);
		int sfd { signalfd(-1, &sigset, 0) };
		logger::log("signal", "info", "signal interceptor registered");
		return sfd;
	}

	int get_listenfd(int port) noexcept 
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
		
		if (int rc = bind(fd, (struct sockaddr *) &addr, sizeof(addr)); rc == -1) {
			logger::log("epoll", "error", "bind() failed  port: $1 description: $2", {std::to_string(port), std::string(strerror(errno))});
			exit(-1);
		}
		listen(fd, SOMAXCONN);
		logger::log("epoll", "info", "listen socket FD: $1 port: $2", {std::to_string(fd), std::to_string(port)});
		return fd;
	}

	void epoll_add_event(int fd, int epoll_fd, uint32_t event_flags) noexcept
	{
		epoll_event event;
		event.data.fd = fd;
		event.events = event_flags;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
	}

	void epoll_handle_close(epoll_event ev) noexcept
	{
		if (ev.data.ptr == nullptr) {
			logger::log("epoll", "error", "EPOLLRDHUP epoll data ptr is null - unable to retrieve request object");
		} else {
			http::request& req = *static_cast<http::request*>(ev.data.ptr);
			req.clear();
			int rc = close(req.fd);
			if (rc == -1)
				logger::log("epoll", "error", "close FAILED for FD: $1 description: $2", {std::to_string(req.fd), std::string(strerror(errno))});
		}
		--g_connections;
	}

	void epoll_handle_connect(int listen_fd, int epoll_fd, std::unordered_map<int, http::request>& buffers) noexcept
	{
		struct sockaddr addr;
		socklen_t len;
		len = sizeof addr;
		int fd { accept4(listen_fd, &addr, &len, SOCK_NONBLOCK) };
		if (fd == -1) {
			logger::log("epoll", "error", "connection accept FAILED for epoll FD: $1 description: $2", {std::to_string(epoll_fd), std::string(strerror(errno))});
		} else {
			++g_connections;
			const char* remote_ip = inet_ntoa(((struct sockaddr_in*)&addr)->sin_addr);
			epoll_event event;
			if (buffers.contains(fd)) {
				http::request& req = buffers[fd];
				req.remote_ip = std::string(remote_ip);
				req.fd = fd;
				req.epoll_fd = epoll_fd;
				event.data.ptr = &req;
			} else {
				auto [iter, success] {buffers.try_emplace(fd, epoll_fd, fd, remote_ip)};
				event.data.ptr = &iter->second;
			}
			event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
			epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
		}
	}

	void epoll_abort_request(http::request& req) noexcept 
	{
		logger::log("epoll", "error", "API not found: $1", {req.path});
		send404(req);
		epoll_event event;
		event.events = EPOLLOUT | EPOLLET | EPOLLRDHUP;
		event.data.ptr = &req;
		epoll_ctl(req.epoll_fd, EPOLL_CTL_MOD, req.fd, &event);		
	}

	void producer(const worker_params& wp) noexcept
	{
		std::scoped_lock lock{m_mutex};
		m_queue.push(wp);
		m_cond.notify_all();
	}

	void run_async_task(http::request& req) noexcept
	{
		if (auto obj = webapi_catalog.find(req.path); obj != webapi_catalog.end()) 
		{
			worker_params wp {req, obj->second};
			producer(wp);
		}
		else 
			epoll_abort_request(req);
	}

	void epoll_handle_read(epoll_event ev, std::array<char, 8192>& data) noexcept
	{
		http::request& req = *static_cast<http::request*>(ev.data.ptr);
		bool run_task {false};
		while (true) 
		{
			int count = read(req.fd, data.data(), data.size());
			if (count == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return;
			}
			if (count > 0) {
				if (read_request(req, data.data(), count)) {
					run_task = true;
					break;
				}
			} else {
				logger::log("epoll", "error", "read error FD: $1 description: $2", {std::to_string(req.fd), std::string(strerror(errno))});
				req.clear();
				return;
			}
		}
		if (run_task)
			run_async_task(req);
	}
	
	void epoll_handle_write(epoll_event ev) noexcept
	{
		http::request& req = *static_cast<http::request*>(ev.data.ptr);
		if (req.response.write(req.fd)) {
			req.clear();
			epoll_event event;
			event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
			event.data.ptr = &req;
			epoll_ctl(req.epoll_fd, EPOLL_CTL_MOD, req.fd, &event);
		}
	}

	void epoll_handle_IO(epoll_event ev, std::array<char, 8192>& data) noexcept
	{
		if (ev.data.ptr == nullptr) {
			logger::log("epoll", "error", "epoll_handle_IO() - epoll data ptr is null");
			return;
		}
		if (ev.events & EPOLLIN) 
			epoll_handle_read(ev, data);
		else 
			epoll_handle_write(ev);
	}


	void start_epoll(int port) noexcept 
	{
		int epoll_fd {epoll_create1(0)};
		logger::log("epoll", "info", "starting epoll FD: $1", {std::to_string(epoll_fd)});

		int listen_fd {get_listenfd(port)};
		
		epoll_add_event(listen_fd, epoll_fd, EPOLLIN);
		epoll_add_event(m_signal, epoll_fd, EPOLLIN);

		std::unordered_map<int, http::request> buffers;
		std::array<char, 8192> data;
		constexpr int MAXEVENTS = 64;
		std::array<epoll_event, MAXEVENTS> events;
		bool exit_loop {false};

		while (true)
		{
			int n_events = epoll_wait(epoll_fd, events.data(), MAXEVENTS, -1);
			for (int i = 0; i < n_events; i++)
			{
				if (events[i].events & EPOLLRDHUP || events[i].events & EPOLLHUP || events[i].events & EPOLLERR)
				{
					epoll_handle_close(events[i]);
				}
				else if (m_signal == events[i].data.fd) //shutdown
				{
					logger::log("signal", "info", "stop signal received for epoll FD: $1 SFD: $2", {std::to_string(epoll_fd), std::to_string(m_signal)});
					exit_loop = true;
					break;
				}
				else if (listen_fd == events[i].data.fd) // new connection.
				{
					epoll_handle_connect(listen_fd, epoll_fd, buffers);
				}
				else // read/write
				{
					epoll_handle_IO(events[i], data);
				}
			}
			if (exit_loop)
				break;
		}

		close(listen_fd);
		logger::log("epoll", "info", "closing listen socket FD: $1", {std::to_string(listen_fd)});
		close(epoll_fd);
		logger::log("epoll", "info", "closing epoll FD: $1", {std::to_string(epoll_fd)});
	}

	void print_server_info(const std::string& pod_name) noexcept 
	{
		logger::log("env", "info", "port: $1", {std::to_string(env::port())});
		logger::log("env", "info", "pool size: $1", {std::to_string(env::pool_size())});
		logger::log("env", "info", "login log: $1", {std::to_string(env::login_log_enabled())});
		logger::log("env", "info", "http log: $1", {std::to_string(env::http_log_enabled())});
		logger::log("env", "info", "jwt exp: $1", {std::to_string(env::jwt_expiration())});
		
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
		
		register_webapi
		(
			webapi_path("/api/ping"), 
			"Healthcheck service for Ingress and Load Balancer",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[](http::request& req) 
			{
				req.response.set_body( R"({"status": "OK"})" );
			},
			false /* no security */
		);
				
		register_webapi
		(
			webapi_path("/api/version"), 
			"Get API-Server version and build date",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[](http::request& req) 
			{
				std::string json;
				std::array<char, 128> hostname{0};
				gethostname(hostname.data(), hostname.size());
				json.append(R"({"status": "OK", "data":[{"pod": ")").append(hostname.data()).append(R"(", )");
				json.append(R"("server": ")").append(SERVER_VERSION).append("-").append(std::to_string(CPP_BUILD_DATE)).append(R"("}]})");
				req.response.set_body(json);
			},
			false /* no security */
		);

		register_webapi
		(
			webapi_path("/api/sysinfo"), 
			"Return global system diagnostics",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[this](http::request& req) 
			{
				std::array<char, 128> hostname{0};
				gethostname(hostname.data(), hostname.size());
				const double avg{ ( g_counter > 0 ) ? g_total_time / g_counter : 0 };
				std::array<char, 64> str1{}; std::to_chars(str1.data(), str1.data() + str1.size(), g_counter);
				std::array<char, 64> str2{}; std::to_chars(str2.data(), str2.data() + str2.size(), avg, std::chars_format::fixed, 8);
				std::array<char, 64> str3{}; std::to_chars(str3.data(), str3.data() + str3.size(), g_connections);
				std::array<char, 64> str4{}; std::to_chars(str4.data(), str4.data() + str4.size(), g_active_threads);
				std::string json {
					logger::format(
						R"({"status": "OK", "data":[{"pod":"$1","totalRequests":$2,"avgTimePerRequest":$3,"connections":$4,"activeThreads":$5}]})",
						{std::string(hostname.data()), std::string(str1.data()), std::string(str2.data()), std::string(str3.data()), std::string(str4.data())}
					)
				};
				req.response.set_body(json);
			},
			false /* no security */
		);
		
		auto prometheus_util = [](const std::vector<std::string>& values) {
			std::string str {
			"# HELP $1 $2.\n"
			"# TYPE $1 counter\n"
			"$1{pod=\"$3\"} $4\n"		
			};
			int i{1};
			for (const auto& v: values) {
				std::string item {"$"};
				item.append(std::to_string(i));
				size_t start_pos = 0;
				while((start_pos = str.find(item, start_pos)) != std::string::npos) {
					str.replace(start_pos, item.length(), v);
					start_pos += v.length();
				}
				++i;
			}
			return str;
		};
		
		register_webapi
		(
			webapi_path("/api/metrics"), 
			"Return metrics in Prometheus format",
			http::verb::GET, 
			{} /* inputs */, 	
			{} /* roles */,
			[&prometheus_util, this](http::request& req) 
			{
				std::string body;
				std::array<char, 128> hostname{0};
				gethostname(hostname.data(), hostname.size());
				const double avg{ ( g_counter > 0 ) ? g_total_time / g_counter : 0 };
				std::array<char, 64> str1{0}; std::to_chars(str1.data(), str1.data() + str1.size(), g_counter);
				std::array<char, 64> str2{0}; std::to_chars(str2.data(), str2.data() + str2.size(), avg, std::chars_format::fixed, 8);
				std::array<char, 64> str3{0}; std::to_chars(str3.data(), str3.data() + str3.size(), g_connections);
				std::array<char, 64> str4{0}; std::to_chars(str4.data(), str4.data() + str4.size(), g_active_threads);
				std::string pod {hostname.data()};
				body.reserve(1027);
				body.append(prometheus_util({"cpp_requests_total", 	"The number of HTTP requests processed by this container.", pod, std::string(str1.data())}));
				body.append(prometheus_util({"cpp_connections", 	"Client tcp-ip connections.", pod, std::string(str3.data())}));
				body.append(prometheus_util({"cpp_active_threads", 	"Active threads.", pod, std::string(str4.data())}));
				body.append(prometheus_util({"cpp_avg_time", 		"Average request processing time in milliseconds.", pod, std::string(str2.data())}));
				req.response.set_body(body, "text/plain; version=0.0.4");
			},
			false /* no security */
		);

		register_webapi
		(
			webapi_path("/api/login"), 
			"Default Login service using a PostgreSQL database",
			http::verb::POST, 
			{
				{"username", http::field_type::STRING, true},
				{"password", http::field_type::STRING, true}
			},
			{} /* roles */,
			[](http::request& req) 
			{
				std::string login{req.get_param("username")};
				std::string password{req.get_param("password")};
				if (auto lr {login::bind(login, password)}; lr.ok()) {
					const std::string token {jwt::get_token(login, lr.get_email(), lr.get_roles())};
					const std::string login_ok {logger::format(R"({"status":"OK","data":[{"displayname":"$1","token_type":"bearer","id_token":"$2"}]})", {lr.get_display_name(), token})};
					req.response.set_body(login_ok);
					if (env::login_log_enabled())
						logger::log("security", "info", "login OK - user: $1 IP: $2 token: $3 roles: $4", {login, req.remote_ip, token, lr.get_roles()}, true);
				} else {
					logger::log("security", "warn", "login failed - user: $1 IP: $2", {login, req.remote_ip}, true);
					const std::string invalid_login = R"({"status": "INVALID", "validation": {"id": "login", "description": "err.invalidcredentials"}})";
					req.response.set_body(invalid_login);
				}
			},
			false /* no security */
		);
	}
	
	void register_webapi(
						const webapi_path& _path, 
						const std::string& _description,
						const http::verb& _verb,
						const std::vector<http::input_rule>& _rules,
						const std::vector<std::string>& _roles,
						const std::function<void(http::request&)>& _fn,
						bool _is_secure = true
						)
	{
		webapi_catalog.try_emplace
		(
			_path.get(),
			_description,
			_verb,
			_rules,
			_roles,
			_fn,
			_is_secure
		);
		std::string msg {_is_secure ? " " : " (insecure) "};
		logger::log("server", "info", "registered $1 WebAPI for path: $2", {msg, _path.get()});
	}

	void register_webapi(
						const webapi_path& _path, 
						const std::string& _description, 
						const http::verb& _verb, 
						const std::function<void(http::request&)>& _fn, 
						bool _is_secure = true
						)
	{
		register_webapi(_path, _description, _verb, {}, {}, _fn, _is_secure);
	}

	void start()
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
			pool[i] = std::jthread(consumer, stops[i].get_token(), this);
		}
		
		start_epoll(port);

		logger::log("server", "info", "$1 shutting down...", {pod_name});
		
		//shutdown workers
		for (const auto& s: stops) {
			s.request_stop();
			{
				std::scoped_lock lock {m_mutex};
				m_cond.notify_all();
			}
		}
		
		for (auto& t:pool)
			t.join();
	}
	
};


#endif /* SERVER_H_ */
