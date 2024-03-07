# API-Server++

Easy to build Web APIs with Modern C++ and a minimal code framework using imperative/functional programming style. Fast, secure, and well-documented.

```
#include "server.h"

int main()
{
	server s;
	
	s.register_webapi
	(
		webapi_path("/api/shippers/view"), 
		"List of shipping companies",
		http::verb::GET, 
		[](http::request& req) 
		{
			std::string sql {"select * from fn_shipper_view()"};
			req.response.set_body(sql::get_json_response("DB1", sql));
		}
	);
	
	s.start();
}
```

This is the declaration of the utility function used to register an API with all its features (a simplified version was used above):
```
	void register_webapi(
		const webapi_path& _path, 
		const std::string& _description, 
		http::verb _verb, 
		const std::vector<http::input_rule>& _rules, 
		const std::vector<std::string>& _roles, 
		std::function<void(http::request&)> _fn,
		bool _is_secure = true
	);
```
You can specify input rules (input parameters, optional), authorized roles (optional), and your lambda function, which most of the time will be very simple, but it can also incorporate additional validations. All this metadata will be used to auto-generate API documentation.

API-Server++ is a compact single-threaded epoll HTTP 1.1 microserver, for serving API requests only (GET/POST/OPTIONS), when a request arrives, the corresponding lambda will be dispatched for execution to a background thread, using the one-producer/many-consumers model. This way API-Server++ can multiplex thousands of concurrent connections with a single thread dispatching all the network-related tasks. API-Server++ is an async, non-blocking, event-oriented server, async because of the way the tasks are dispatched, it returns immediately to keep processing network events, while a background thread picks the task and executes it. The kernel will notify the program when there are events to process, in which case, non-blocking operations will be used on the sockets, and the program won't consume CPU while waiting for events, this way a single-threaded server can serve thousands of concurrent clients if the I/O tasks are fast. The size of the workers' thread pool can be configured via environment variable, the default is 4, which has proved to be good enough for high loads on VMs with 4-6 virtual cores.

API-Server++ was designed to be run as a container on Kubernetes, with a stateless security/session model based on JSON web token (good for scalability), and built-in observability features for Grafana stack, but it can be run as a regular program on a terminal or as a SystemD Linux service, on production it will run behind an Ingress or Load Balancer providing TLS and Layer-7 protection.

It uses the native PostgreSQL client C API `libpq` for maximum speed, as well as `libcurl` for secure email and `openssl v3` for JWT signatures. It expects a JSON response from queries returning data, which is very easy to do using PostgreSQL functions.

![webapi helloworld](https://github.com/cppservergit/apiserver/assets/126841556/40fcc7fb-533e-429e-aea0-d87923f58a01)


## Requirements

The test environment is Ubuntu 23.04 with GCC 13.1, We used Canonical's Multipass VMs on Windows 10 Pro, it's a very agile tool for managing lightweight VMs on Windows, you can create an Ubuntu 23.04 VM using a command like this, with very few resources:
```
multipass launch -n testvm -c 4 -m 2g -d 6g lunar
```
If you are not going to update the whole operating system then you can use `-d 4g` for 4GB of disk space.

Update Ubuntu package list:
```
sudo apt update
```

Install required packages:
```
sudo apt install g++-13 libssl-dev libpq-dev libcurl4-openssl-dev uuid-dev libjson-c-dev libldap-dev make -y --no-install-recommends
```

Optionally, you can upgrade the rest of the operating system, it may take some minutes and require a restart of the VM:
```
sudo apt upgrade -y
```

__Note__: You can run API-Server++ on Ubuntu 22.04 if you create a native Linux LXD container with Ubuntu 23.04 to run the API-Server++ binary and use HAProxy as the HTTPS front on Ubuntu 22.04 (the server host OS), this way you can run on a reliable LTS Ubuntu server, and also protect network access to API-Server++, which is only visible from the host via HAProxy.

![image](https://github.com/cppservergit/apiserver/assets/126841556/2cfacfdc-6eba-4698-b2b9-b3a1ffa88fbd)

API-Server++ requires GCC 13.1 or newer because it does take advantage of the latest C++ 20/23 standard features that are only supported by GCC 13.1 onwards, like `<format>`, constexpr strings and functions, ranges, and more.

### PostgreSQL testdb setup

Download TestDB backup:
```
curl https://cppserver.com/files/apiserver/testdb.backup -O
```

Please restore this backup in your PostgreSQL server, this database contains a sample schema with several tables to exercise different kinds of APIs, it also contains the minimal security tables and the stored procedure `cpp_dblogin` to support an SQL-based login mechanism, so you can test API-Server++ JWT (JSON web token) implementation.

#### Using PostgreSQL as a docker container

If you have a VM with docker, you can quickly install PostgreSQL using this command, change the password if you want but take care to use your new password in the commands following below:
```
sudo docker run --restart unless-stopped --name pgsql --network host -e POSTGRES_PASSWORD=basica -d postgres:latest
```
The command above will create a container named `pgsql`, and the `postgres` user password will be `basica`.

If you are using PostgreSQL as a docker container, you can use this command to create TestDB and then restore the backup, change host and password to meet your settings:
```
sudo docker exec -e PG_PASSWORD=basica pgsql psql -h localhost -U postgres -c 'create database testdb;'
```

Restore:
```
cat testdb.backup | sudo docker exec -i -e PG_PASSWORD=basica pgsql pg_restore -d testdb -h localhost -U postgres
```

If you already have a PostgreSQL server running somewhere, just create `testdb` and restore the backup.

Take note of your PostgreSQL hostname or IP address, you will need it to configure the script used to run API-Server++.

## Build

Retrieve latest version of API-Server++
```
git clone https://github.com/cppservergit/apiserver
```

Navigate into API-Server++ directory
```
cd apiserver
```

Compile and build executable
```
make
```

Expected output:
```
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/env.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/logger.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/jwt.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/httputils.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/sql.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/login.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -DCPP_BUILD_DATE=20230807 -c src/server.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/main.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel env.o logger.o jwt.o httputils.o sql.o login.o server.o main.o -lpq -lcurl -lcrypto -luuid -ljson-c -o "apiserver"
```

## Run API-Server++

Please edit run script and fix the PostgreSQL connection strings to meet your environment:
```
nano run
```

Search for these entries:

```
# PGSQL authenticator config
export CPP_LOGINDB="host=demodb.mshome.net port=5432 dbname=testdb connect_timeout=10 user=postgres password=basica application_name=CPPServer"
# PGSQL data sources
export DB1="host=demodb.mshome.net port=5432 dbname=testdb connect_timeout=10 user=postgres password=basica application_name=CPPServer"
```

Default script:
```
#!/bin/bash
export CPP_LOGIN_LOG=1
export CPP_HTTP_LOG=1
export CPP_PORT=8080
export CPP_POOL_SIZE=4
# JWT config
export CPP_JWT_SECRET="basica"
export CPP_JWT_EXP=600
# PGSQL authenticator config
export CPP_LOGINDB="host=demodb.mshome.net port=5432 dbname=testdb connect_timeout=10 user=postgres password=basica application_name=CPPServer"
# PGSQL data sources
export DB1="host=demodb.mshome.net port=5432 dbname=testdb connect_timeout=10 user=postgres password=basica application_name=CPPServer"
# secure mail config
export CPP_MAIL_SERVER="smtp://smtp.gmail.com:587"
export CPP_MAIL_USER="admin@martincordova.com"
export CPP_MAIL_PWD="your-smtp-password"
# LDAP authenticator config
export CPP_LDAP_URL="ldap://demodb.mshome.net:1389/"
export CPP_LDAP_ADMIN_USER_DN="cn=admin,dc=example,dc=org"
export CPP_LDAP_ADMIN_PWD="basica"
export CPP_LDAP_USER_DN="cn={userid},ou=users,dc=example,dc=org"
export CPP_LDAP_USER_BASE="ou=users,dc=example,dc=org"
export CPP_LDAP_USERGROUPS_BASE="ou=users,dc=example,dc=org"
export CPP_LDAP_USER_FILTER="(userid={userid})"
export CPP_LDAP_USERGROUPS_FILTER="(member={dn})"
./apiserver
```
CRTL-x to save your changes.

Make it executable:
```
chmod +x run
```

Run API-Server++
```
./run
```

Expected output:
```
{"source":"signal","level":"info","msg":"signal interceptor registered"}
{"source":"server","level":"info","msg":"registering built-in diagnostic and security services...","thread":"140336593955712","x-request-id":""}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/ping","thread":"140336593955712","x-request-id":""}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/version","thread":"140336593955712","x-request-id":""}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/sysinfo","thread":"140336593955712","x-request-id":""}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/metrics","thread":"140336593955712","x-request-id":""}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/login","thread":"140336593955712","x-request-id":""}
{"source":"env","level":"info","msg":"port: 8080","thread":"140336593955712","x-request-id":""}
{"source":"env","level":"info","msg":"pool size: 4","thread":"140336593955712","x-request-id":""}
{"source":"env","level":"info","msg":"login log: 0","thread":"140336593955712","x-request-id":""}
{"source":"env","level":"info","msg":"http log: 0","thread":"140336593955712","x-request-id":""}
{"source":"env","level":"info","msg":"jwt exp: 600","thread":"140336593955712","x-request-id":""}
{"source":"server","level":"info","msg":"Pod: lunar PID: 4510 starting API-Server++ v1.0.5-20231009","thread":"140336593955712","x-request-id":""}
{"source":"server","level":"info","msg":"hardware threads: 4 GCC: 13.1.0","thread":"140336593955712","x-request-id":""}
{"source":"epoll","level":"info","msg":"starting epoll FD: 4","thread":"140336593955712","x-request-id":""}
{"source":"epoll","level":"info","msg":"listen socket FD: 5 port: 8080","thread":"140336593955712","x-request-id":""}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"140336593942208","x-request-id":""}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"140336585549504","x-request-id":""}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"140336577156800","x-request-id":""}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"140336442939072","x-request-id":""}
```

## Test connection to API-Server++

Open another terminal on your VM and execute:
```
curl localhost:8080/api/version
```

Expected output:
```
{"status": "OK", "data":[{"pod": "test", "server": "API-Server++ v1.0.0-20230807"}]}
```

## Test login API and JWT

Test login API (tables s_user, s_role and s_user_role store the security configuration in the public schema of testdb):
```
curl localhost:8080/api/login -F "username=mcordova" -F "password=basica"
```

Expected output (token will vary):
```
{"status":"OK","data":[{"displayname":"Martín Córdova","token_type":"bearer","id_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbiI6Im1jb3Jkb3ZhIiwibWFpbCI6ImNwcHNlcnZlckBtYXJ0aW5jb3Jkb3ZhLmNvbSIsInJvbGVzIjoiY2FuX2RlbGV0ZSwgY2FuX3VwZGF0ZSwgc3lzYWRtaW4iLCJleHAiOjE2OTE0NTQ1OTl9.M2i47hipMt9CxlPPA1zNeIpVIJiPfsMSiVJe0G7ZXHE"}]}
```

## Hello World - your first API

On the same terminal windows where API-Server++ is running, please press CTRL-C to stop the server, now edit main.cpp in order to add your first API definition:
```
nano src/main.cpp
```

Add this code below `server s;` and right above `s.start();`:
```
	s.register_webapi
	(
		webapi_path("/api/shippers/view"), 
		"List of shipping companies",
		http::verb::GET, 
		{} /* inputs */, 	
		{} /* roles */,
		[](http::request& req) 
		{
			req.response.set_body( sql::get_json_response("DB1", "select * from fn_shipper_view()") );
		}
	);
```
CTRL-x to exit and save.
With one line of code, we define a new API, with some metadata including a description, the HTTP method supported, input rules validation if any, authorized roles if any, and most importantly, a lambda function with the code implementing the API, a one-liner in this case, thanks to the high-level abstractions of API-Server++.

The function `sql::get_json_response()` executes a query that MUST return JSON straight from the database, in the specific case of the HelloWorld example the SQL function looks like this:

```
CREATE OR REPLACE FUNCTION public.fn_shipper_view()
    RETURNS TABLE(json character varying) 
    LANGUAGE 'sql'
    COST 100
    VOLATILE SECURITY DEFINER PARALLEL UNSAFE
    ROWS 1000

AS $BODY$

	select array_to_json(array_agg(row_to_json(d))) from
		(SELECT
			shipperid,
			companyname,
			phone
		FROM 
			demo.shippers
		ORDER BY
			companyname) d
$BODY$;

ALTER FUNCTION public.fn_shipper_view()
    OWNER TO postgres;
```
The public schema of TestDB contains several examples of functions that return JSON, including this one, your own SQL functions should follow this pattern because API-Server++ relies on the Database to generate the JSON output from queries returning resultsets, this applies to this native-PostgreSQL version, not for the ODBC version, more on this later at the end of this README.

The whole program should look like this:
```
#include "server.h"

int main()
{
	server s;
        s.register_webapi
        (
                webapi_path("/api/shippers/view"),
                "List of shipping companies",
                http::verb::GET,
                {} /* inputs */,
                {} /* roles */,
                [](http::request& req)
                {
                        req.response.set_body( sql::get_json_response("DB1", "select * from fn_shipper_view()") );
                }
        );

        s.start();
}
```

Now recompile, only the main.cpp module will be recompiled and the program relinked with the object files, it's a quick operation:
```
make
```

Expected output:
```
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/main.cpp
g++-13 -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel env.o logger.o jwt.o httputils.o sql.o login.o server.o main.o -lpq -lcurl -lcrypto -luuid -ljson-c -o "apiserver"
```

Now run the server again:
```
./run
```

Now starting the log output (2nd line) you should see this line:
```
{"source":"server","level":"info","msg":"registered WebAPI for path: /api/shippers/view"}
```

Now that the API-Server++ is running again and your API has been published, let's test it with CURL in the 2nd terminal we used before, first, we need to login to obtain a [JWT token](https://jwt.io/introduction), otherwise, any attempt to invoke your API will be rejected with HTTP status code 401 (login required error).

```
curl localhost:8080/api/login -F "username=mcordova" -F "password=basica"
```

Expected output:
```
{"status":"OK","data":[{"displayname":"Martín Córdova","token_type":"bearer","id_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbiI6Im1jb3Jkb3ZhIiwibWFpbCI6ImNwcHNlcnZlckBtYXJ0aW5jb3Jkb3ZhLmNvbSIsInJvbGVzIjoiY2FuX2RlbGV0ZSwgY2FuX3VwZGF0ZSwgc3lzYWRtaW4iLCJleHAiOjE2OTE0Njc3MTR9.18g9mAXNkbXAxxP1i6rGKR1IKWAIuLpFAAkwaN8Jmjc"}]}
```

Mark and copy the token value only, without the quotes, in this example, it would be:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbiI6Im1jb3Jkb3ZhIiwibWFpbCI6ImNwcHNlcnZlckBtYXJ0aW5jb3Jkb3ZhLmNvbSIsInJvbGVzIjoiY2FuX2RlbGV0ZSwgY2FuX3VwZGF0ZSwgc3lzYWRtaW4iLCJleHAiOjE2OTE0Njc3MTR9.18g9mAXNkbXAxxP1i6rGKR1IKWAIuLpFAAkwaN8Jmjc
```

Now invoke your HelloWorld API with curl, passing the proper header with the token, something like `-H "Authorization: Bearer xyz123..."`
```
curl localhost:8080/api/shippers/view -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbiI6Im1jb3Jkb3ZhIiwibWFpbCI6ImNwcHNlcnZlckBtYXJ0aW5jb3Jkb3ZhLmNvbSIsInJvbGVzIjoiY2FuX2RlbGV0ZSwgY2FuX3VwZGF0ZSwgc3lzYWRtaW4iLCJleHAiOjE2OTE0Njc3MTR9.18g9mAXNkbXAxxP1i6rGKR1IKWAIuLpFAAkwaN8Jmjc"
```

Expected output:
```
{"status":"OK", "data":[{"shipperid":503,"companyname":"Century 22 Courier","phone":"800-WE-CHARGE"},{"shipperid":13,"companyname":"Federal Courier Venezuela","phone":"555-6728"},{"shipperid":3,"companyname":"Federal Shipping","phone":"(503) 555-9931"},{"shipperid":1,"companyname":"Speedy Express","phone":"(503) 555-9831"},{"shipperid":2,"companyname":"United Package","phone":"(505) 555-3199"},{"shipperid":501,"companyname":"UPS","phone":"500-CALLME"}]}
```

The token gets validated by API-Server++ before executing your lambda, it has a default duration of 10 minutes and it can be configured via environment variable, in a Kubernetes-friendly way, in any case, authentication and authorization are transparent to your API and always enforced. All registered APIs are secure by default unless explicitly disabled, in this case, a clear message will be recorded in the logs when registering the API:
```
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/ping"}
```

### Testing with Javascript in the browser console

It's good to know how to test your APIs the "manual way" using CURL, but when passing the security token is required, it becomes a bit tedious, we can use a very simple HTML page with a bit of modern Javascript to automate API testing including security. For this exercise's sake we will assume that you are in your desktop environment, where you can use a browser to connect to the VM running your API, API-Server++ must be running on your Linux VM. 
Open the browser and navigate to this URL (PLEASE use your VM IP address or the hostname if you are using Canonical's Multipass VMs on Windows 10 Pro):
```
http://your_VM_address:8080/api/sysinfo
```

Expected output on the browser page:
```
{"status": "OK", "data":[{"pod":"test","totalRequests":69,"avgTimePerRequest":0.00050976,"connections":2,"activeThreads":1}]}
```

There is another built-in API to serve metrics in a Prometheus-compatible format:
```
http://your_VM_address:8080/api/metrics
```

Expected output on the browser page:
```
# HELP cpp_requests_total The number of HTTP requests processed by this container.
# TYPE cpp_requests_total counter
cpp_requests_total{pod="test"} 70
# HELP cpp_connections Client tcp-ip connections.
# TYPE cpp_connections counter
cpp_connections{pod="test"} 2
# HELP cpp_active_threads Active threads.
# TYPE cpp_active_threads counter
cpp_active_threads{pod="test"} 1
# HELP cpp_avg_time Average request processing time in milliseconds.
# TYPE cpp_avg_time counter
cpp_avg_time{pod="test"} 0.00050264
```

Now that we verified that the connection to API-Server++ is OK, let's create an HTML file test.html on your disk, add this content, change the value of the _SERVER_ variable (see the beginning of the `script` section) and save it:
```
<!doctype html>
	<head>
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css">
		<title>JSON API tester</title>
	</head>

<html>
	<main class="container">
	<article>
		<h1>Please open the console with [shift+ctrl+i]</h1>
	</article>
	</main>
</html>

<script>
	// REMEMBER TO CHANGE THIS to point to your Ubuntu VM running API-Server++ !!!
	const _SERVER_ = "http://test.mshome.net:8080";

	onload = async function() {
		//login
		const loginForm = new FormData();
		loginForm.append("username", "mcordova");
		loginForm.append("password", "basica");
		//call and wait for login to return
		await call_api("/api/login", function(json) {
				console.log("User: " + json.data[0].displayname);
				console.log("Token: " + json.data[0].id_token);
				sessionStorage.setItem("token", json.data[0].id_token); //store token for next request
			}, loginForm);

		//call hello world API
		call_api("/api/shippers/view", function(json) {
					console.table(json.data); //print resultset to console
				});
	}

	async function call_api(uri, fn, formData)
	{
		try {
			const token = sessionStorage.getItem("token");
			const auth = "Bearer " + sessionStorage.getItem("token");
			let headers = {};
			if (token != "")
				headers = { 'Authorization': auth };
			
			let options;
			if (formData === undefined)
				options = {method: 'GET', mode: 'cors', headers};
			else
				options = {method: 'POST', mode: 'cors', headers,  body: formData};

			const res = await fetch(_SERVER_ + uri, options);
			if (res.ok) {
				const json = await res.json();
				console.log("TEST " + uri + " HTTP status: " + res.status + " JSON status: " + json.status);
				if (json.status == "OK") {
					fn(json);
				} else if (json.status == "EMPTY") {
					console.log("Data not found");
				} else if (json.status == "INVALID") {
					console.log("Service data validation error: " + json.validation.description + " id: " + json.validation.id);
				} else if (json.status == "ERROR") {
					console.log("Service error: " + json.description);
				}
			} else
				if (res.status == 401)
					console.log("Authentication required: please login");
				else
					console.log("HTTP error code: " + res.status);
		} catch (error) {
			console.log("Connection error: " + error.message);
		}
	}
</script>
```

Now double-click on the file to open it in the browser, and press `shift+ctrl+i` to open de developer tools, the console in particular, refresh the page several times and watch the results.
The `call_api()` function is a very handy testing tool that you can use as the base code to invoke your APIs or to use a page like this for quickly unit-testing your APIs, it is far less cumbersome than using CURL alone and you can take advantage of the browser's developer tools.

If you check you API-Server++ terminal you will see some log entries like these:
```
{"source":"security","level":"info","msg":"login OK - user: mcordova IP: 172.19.80.1 token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbiI6Im1jb3Jkb3ZhIiwibWFpbCI6ImNwcHNlcnZlckBtYXJ0aW5jb3Jkb3ZhLmNvbSIsInJvbGVzIjoiY2FuX2RlbGV0ZSwgY2FuX3VwZGF0ZSwgc3lzYWRtaW4iLCJleHAiOjE2OTE0NzM3MTl9.7z495wh6csYCavjxLK6-QIUWYWeFO2nLLQCI4gh44ts roles: can_delete, can_update, sysadmin","thread":"140455100950080"}
{"source":"access-log","level":"info","msg":"fd=13 remote-ip=172.19.80.1 POST path=/api/login elapsed-time=0.000907 user=","thread":"140455100950080"}
{"source":"access-log","level":"info","msg":"fd=13 remote-ip=172.19.80.1 OPTIONS path=/api/shippers/view elapsed-time=0.000007 user=","thread":"140455084164672"}
{"source":"access-log","level":"info","msg":"fd=10 remote-ip=172.19.80.1 OPTIONS path=/api/version elapsed-time=0.000004 user=","thread":"140455084164672"}
{"source":"access-log","level":"info","msg":"fd=13 remote-ip=172.19.80.1 OPTIONS path=/api/sysinfo elapsed-time=0.000006 user=","thread":"140455092557376"}
{"source":"access-log","level":"info","msg":"fd=14 remote-ip=172.19.80.1 GET path=/api/version elapsed-time=0.000007 user=","thread":"140455092557376"}
{"source":"access-log","level":"info","msg":"fd=10 remote-ip=172.19.80.1 GET path=/api/shippers/view elapsed-time=0.000601 user=mcordova","thread":"140455084164672"}
{"source":"access-log","level":"info","msg":"fd=13 remote-ip=172.19.80.1 GET path=/api/sysinfo elapsed-time=0.000008 user=","thread":"140455075771968"}
```

You can configure the log to be less verbose by changing the environment variables in the `run` script, which is recommended for production because it has overhead and the Ingress/Load Balancer will produce entries like these anyway, there is no need to duplicate them.
```
export CPP_LOGIN_LOG=0
export CPP_HTTP_LOG=0
```
__Note__: warnings and error log entries cannot be disabled.

## Retrieving multiple resultsets

Our TestDB backend contains a function that returns a JSON response containing a customer's record and the cutomer's orders given a customer ID:
```
CREATE OR REPLACE FUNCTION public.fn_customer_get(id character varying)
    RETURNS TABLE(json character varying) 
    LANGUAGE 'plpgsql'
    COST 100
    VOLATILE SECURITY DEFINER PARALLEL UNSAFE
    ROWS 1

AS $BODY$
	declare q1 varchar;
	declare q2 varchar;
	declare q varchar;
BEGIN
	select array_to_json(array_agg(row_to_json(t1))) into q1
	from (select customerid, contactname, companyname, city, country, phone from demo.customers where customerid = id) t1;
 
	select array_to_json(array_agg(row_to_json(t2))) into q2
	from (select orderid, orderdate, shipcountry, shipper, total from vw_custorders where customerid = id order by orderid) t2;

 	if q2 is null then
		q := '{"customer":' || q1 || ',' || '"orders":[]}';
	else
		q := '{"customer":' || q1 || ',' || '"orders":' || q2 || '}';
	end if;
	
	RETURN QUERY select CAST(q as varchar) as json;
	return;
END;
$BODY$;

ALTER FUNCTION public.fn_customer_get(character varying)
    OWNER TO postgres;
```

This SQL function is quite more verbose than in the HelloWorld example, but the required code in API-Server++ is barely more complex, now we need to define an input parameter to pass to the SQL function (an input rule), that's all.

Stop the server with CTRL-C and edit main.cpp:
```
nano src/main.cpp
```

Add this code right above s.start()
```
	s.register_webapi
	(
		webapi_path("/api/customer/info"), 
		"Retrieve customer record and the list of his purchase orders",
		http::verb::GET, 
		{ /* inputs */
			{"customerid", http::field_type::STRING, true}
		}, 	
		{} /* roles */,
		[](http::request& req)
		{
			req.response.set_body(sql::get_json_response("DB1", req.get_sql("select * from fn_customer_get($customerid)")));
		}
	);
```
As you can see, this API expects an input parameter named `customerid`, of type `STRING` and it is required, MUST be included in the invocation as a URI parameter, something like:

```
http://YouServer:8080/api/customer/info?customerid=BOLID
```

The whole program should look like this:
```
#include "server.h"

int main()
{
	server s;
        s.register_webapi
        (
                webapi_path("/api/shippers/view"),
                "List of shipping companies",
                http::verb::GET,
                {} /* inputs */,
                {} /* roles */,
                [](http::request& req)
                {
                        req.response.set_body( sql::get_json_response("DB1", "select * from fn_shipper_view()") );
                }
        );

	s.register_webapi
	(
		webapi_path("/api/customer/info"), 
		"Retrieve customer record and the list of his purchase orders",
		http::verb::GET, 
		{ /* inputs */
			{"customerid", http::field_type::STRING, true}
		}, 	
		{} /* roles */,
		[](http::request& req)
		{
			req.response.set_body(sql::get_json_response("DB1", req.get_sql("select * from fn_customer_get($customerid)")));
		}
	);

        s.start();
}
```

CTRL-X to save and exit. Recompile:
```
make
```

Expected output:
```
g++-13 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -I/usr/include/postgresql -c src/main.cpp
g++-13 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel env.o logger.o jwt.o httputils.o sql.o login.o server.o main.o -lpq -lcurl -lcrypto -o "apiserver"
```

Run the new version:
```
./run
```

The program log should contain these lines at the beginning:
```
{"source":"signal","level":"info","msg":"signal interceptor registered"}
{"source":"server","level":"info","msg":"registered WebAPI for path: /api/shippers/view"}
{"source":"server","level":"info","msg":"registered WebAPI for path: /api/customer/info"}
```

You new API has been registered and is ready for testing, you can use your HTML page, test.html, just add these lines to the tester code:
```
		call_api("/api/customer/info?customerid=BOLID", function(json) {
					console.table(json.data.customer); 
					console.table(json.data.orders); 
				});
```
We know that the SQL function returns 2 resultsets (JSON arrays) with specific names `customer` and `orders`, because of that we know how to properly show the response. In other words, we must have this knowledge in order to process the response, many of these SQL functions will return a single JSON array named `data`, but for the case of more than one resultset, `data` becomes the wrapper field of the inner JSON arrays.

This is the JSON response for this case:
```
{
	"status": "OK",
	"data": {
		"customer": [{
			"customerid": "BOLID",
			"contactname": "Martín Sommer",
			"companyname": "Bólido Comidas preparadas",
			"city": "Madrid",
			"country": "Spain",
			"phone": "(91) 555 22 82"
		}],
		"orders": [{
			"orderid": 10326,
			"orderdate": "1994-11-10",
			"shipcountry": "Spain",
			"shipper": "United Package",
			"total": 982
		}, {
			"orderid": 10801,
			"orderdate": "1996-01-29",
			"shipcountry": "Spain",
			"shipper": "United Package",
			"total": 3026.85
		}, {
			"orderid": 10970,
			"orderdate": "1996-04-23",
			"shipcountry": "Spain",
			"shipper": "Speedy Express",
			"total": 224
		}]
	}
}
```

If you want to view the raw JSON response just add this line to your Javascript test handler:
```
console.log(JSON.stringify(json));
```

Example:
```
		call_api("/api/customer/info?customerid=BOLID", function(json) {
					console.log(JSON.stringify(json));
					console.table(json.data.customer); 
					console.table(json.data.orders); 
				});
```

## API Examples

The TestDB database has many functions that return JSON and can be used to create APIs, but also stored procedures that modify data (insert/update/delete) and won't return JSON, just execute SQL that should not return any results. There is an example of main.cpp with all the API definitions for this sample database, also an HTML5/CCS3 web responsive frontend to consume these APIs, more on this later. In the following sections you will find different types of Web API definitions, using more features than the examples above.

### Invoke stored procedure to insert or update record

```
	s.register_webapi
	(
		webapi_path("/api/gasto/add"), 
		"Add expense record",
		http::verb::POST, 
		{
			{"fecha", http::field_type::DATE, true},
			{"categ_id", http::field_type::INTEGER, true},
			{"monto", http::field_type::DOUBLE, true},
			{"motivo", http::field_type::STRING, true}			
		},
		{},
		[](http::request& req) 
		{
			sql::exec_sql("DB1", req.get_sql("call sp_gasto_insert($fecha, $categ_id, $monto, $motivo)"));
			req.response.set_body("{\"status\": \"OK\"}");
		}
	);
```
Input rules are defined for each field, the name, the data type expected, and if it is required or optional, the name will be used to replace the value in the SQL template when using the `req.get_sql`, APi-Server++ takes care of pre-processing the fields to ensure that no SQL-injection attacks so they can be safely replaced into the SQL template. A multipart form POST is the only verb accepted for this API. With this definition of the API, the Server will take care of processing the request and validating the inputs as well as the security (authentication/authorization if roles were defined), when all the preconditions are met, then the lambda function will be executed.

When the API executes a procedure that modifies data and does not return any resultsets, then a minimal JSON response with OK status is all that needs to be returned.

The case for using a procedure that updates a record is very similar, but in this case we used the roles field to set authorization restrictions, only users with the specified roles (can_update) can invoke this Web API:
```
	s.register_webapi
	(
		webapi_path("/api/gasto/update"), 
		"Update expense record",
		http::verb::POST, 
		{
			{"gasto_id", http::field_type::INTEGER, true},
			{"fecha", http::field_type::DATE, true},
			{"categ_id", http::field_type::INTEGER, true},
			{"monto", http::field_type::DOUBLE, true},
			{"motivo", http::field_type::STRING, true}			
		},
		{"can_update"},
		[](http::request& req) 
		{
			auto sql {req.get_sql("call sp_gasto_update($gasto_id, $fecha, $categ_id, $monto, $motivo)")};
			sql::exec_sql("DB1", sql);
			req.response.set_body("{\"status\": \"OK\"}");
		}
	);
```

The stored procedure that serves as the backend to this Web API:
```
CREATE OR REPLACE PROCEDURE public.sp_gasto_update(
	IN gasto_id integer,
	IN fecha date,
	IN categ_id integer,
	IN monto double precision,
	IN motivo character varying)
LANGUAGE 'sql'
AS $BODY$

		UPDATE demo.gasto SET
			fecha=$2,
			categ_id=$3,
			monto=$4,
			motivo=$5
		WHERE
			gasto_id=$1
			
$BODY$;
ALTER PROCEDURE public.sp_gasto_update(integer, date, integer, double precision, character varying)
    OWNER TO postgres;
```

### Search filter API

This API executes an SQL function that returns a JSON response, sales by category for a period of time, the date-from/date-to parameters are the input rules for this API:
```
	s.register_webapi
	(
		webapi_path("/api/sales/query"), 
		"Sales report by category in a time interval",
		http::verb::POST, 
		{
			{"date1", http::field_type::DATE, true},
			{"date2", http::field_type::DATE, true}
		},
		{"report", "sysadmin"},
		[](http::request& req) 
		{
			auto sql {req.get_sql("select * from fn_sales_by_category($date1, $date2)")};
			std::string json {sql::get_json_response("DB1", sql)};
			req.response.set_body(json);
		}
	);
```
The backend SQL function may be of a certain complexity, but it's hidden from the API implementation, as long as it returns JSON, we are good.
In this example we also used a list of authorized roles, the user invoking the API must belong to any of those roles, otherwise, execution will be denied and a JSON response with the status INVALID will be returned.
If you want to test this API, there is data for dates between 1994-01-01 and 1996-12-31.

### Delete record API with additional custom validator

This API will invoke a stored procedure to delete a record, but instead of waiting for the database to raise an error if there is a violation of referential integrity, the API implements a custom validator rule using a lambda inside the main function body, this way an INVALID status with a specific message may be returned instead of an ERROR:
```
	s.register_webapi
	(
		webapi_path("/api/categ/delete"), 
		"Delete category record",
		http::verb::GET, 
		{{"id", http::field_type::INTEGER, true}},
		{"can_delete"},
		[](http::request& req) 
		{
			//validator for referential integrity
			req.enforce("_dialog_", "$err.delete", [&req]()-> bool { 
				return !sql::has_rows("DB1", req.get_sql("select * from fn_categ_in_use($id)"));
			});
			sql::exec_sql("DB1", req.get_sql("call sp_categ_delete($id)"));
			req.response.set_body("{\"status\": \"OK\"}");
		}
	);
```
The `req.enforce()` method evaluates the result of the passed code (validator), if false then stops execution of the API and the client will receive a JSON response with status INVALID and the fields passed to this method (first two arguments). In this example, the validator checks if this category ID is being used in another table, the SQL logic for this is encapsulated in the fn_categ_in_use() function, which does not return JSON but a regular resultset, the `sql::has_rows()` returns true if the resultset contains at least 1 row. This example shows how custom validation/pre-condition rules can be applied inside an API, and if any of these custom validators return false then the rest of the code won't be executed, that's the guarantee enforced by API-Server++.

### Sending email

API-Server++ uses libcurl to send mail with secure SMTP (TLS), this has been tested with GMail's server using a google workspace account. In order to use this feature you have to configure the corresponding environment variables with correct values (edit the `run` bash script):
```
# secure mail config
export CPP_MAIL_SERVER="smtp://smtp.gmail.com:587"
export CPP_MAIL_USER="admin@martincordova.com"
export CPP_MAIL_PWD="your-smtp-password"
```

A new thread will be used to send the email, this way your function returns immediately without blocking the thread that's executing your API function, and the server can send the response to the client and keep processing requests. Any error returned by `libcurl` will be recorded in the logs. It's recommended practice to invoke the `send_mail()` function after executing your database I/O and the `set_body()` function. If any error occurs doing I/O, the `send_mail()` will never be called. Mail delivery errors will be probably notified to the sender address, that is the address configured in the `CPP_MAIL_USER` environment variable.

The http::request class provides several functions to send a mail with more or fewer arguments (CC, attachments, etc) to make the code simpler whenever possible.

Example of simple invocation without CC and no attachment:
```
	server s;
	s.register_webapi
	(
		webapi_path("/api/gasto/add"), 
		"Add expense record",
		http::verb::POST, 
		{
			{"fecha", http::field_type::DATE, true},
			{"categ_id", http::field_type::INTEGER, true},
			{"monto", http::field_type::DOUBLE, true},
			{"motivo", http::field_type::STRING, true}			
		},
		{},
		[](http::request& req) 
		{
			sql::exec_sql("DB1", req.get_sql("call sp_gasto_insert($fecha, $categ_id, $monto, $motivo)"));
			req.response.set_body("{\"status\": \"OK\"}");
			req.send_mail(
					req.user_info.mail, //TO
					"Document uploaded via API-Server++",
					"expenditure-msg.html"
				);			
		}
	);
```
You can obtain the current user email using `req.user_info.mail`. The body of the message must be an HTML document that you provide, it must be stored in /var/mail, and it can contain parameter markers corresponding to the input fields, these are used like in the SQL template: $fieldname. The `send_mail()` function takes care of loading the template and injecting input fields if necessary.

There is a variant of the `send_mail()` function that accepts a CC argument, and also with single attachment:
```
void send_mail(const std::string& to, const std::string& cc, const std::string& subject, const std::string& body);
```

The code below sends an email with an attachment:
```
			req.send_mail(
					req.user_info.mail, //TO
					"cppserver@martincordova.com", //CC - can be empty
					"Document uploaded via API-Server++",
					"upload-msg.html",
					req.get_param("document"), //attachment
					req.get_param("filename") //original filename
				);	
```
In this particular example, a file was uploaded using API-Server++ automatic upload facility, it does store the file with a unique UUID name in a storage area using the path `/var/blobs`, on Kubernetes this is only a path mapped to a shared storage service, when running native on Linux this may be the actual directory or an NFS mount.
The `req.get_param("document")` call returns the UUID name of the uploaded file, we also provide the original filename so the attachment will be properly named inside the mail. If we use an absolute path like "/mydir/myfile.pdf" then the `send_mail` function won't assume this is a blob, it will try to load the file from the path provided and the last parameter can be passed as an empty string `""`.
The example above was tailored to the case of blob uploads, where files are stored in a directory mapped to `/var/blobs` using an auto-generated UUID as the file name and the rest of the parameters are stored in a table using a stored procedure, you may want to create a sort of feedback sending an email notifying the occurrence of the upload, the uploaded file and its basic information (title, size, etc).

## Demo App

There is a complete Demo case, frontend, and backend, you should download both to play with it:

* [Demo Web Responsive App](https://cppserver.com/files/apiserver/demo.zip)
* [main.cpp](https://cppserver.com/files/apiserver/main-pgsql.cpp)

Instructions:

1) Backend: download main.cpp into /apiserver/src and recompile with `make`. CD to the directory `/apiserver`, make sure the server is not running and then execute:
```
curl https://cppserver.com/files/apiserver/main-pgsql.cpp -o src/main.cpp
make
```

2) Frontend: unzip demo.zip, the Demo HTML5 WebApp, edit /www/js/utils.js to point the _SERVER_ variable to your API-Server++ and double-click on index.html, log in with user mcordova/basica and play with it. This is a responsive webapp with several cool features. You don't need a web server to access this static website, the browser can use it straight from the filesystem.

![ui](https://github.com/cppservergit/apiserver/assets/126841556/36b7910d-937e-45d1-a4b4-f5748a90cbb0)

### Uploads

For testing the upload feature you need to create /var/blobs on your VM and assign permissions so API-Server++ can read/write files into that directory:
```
sudo mkdir /var/blobs
sudo chmod 777 /var/blobs
```

When using API-Server++ as a container on Kubernetes, volumes and volume mappings will be used to map /var/blobs to the actual storage destination on the Kubernetes Cluster. This is transparent to API-Server++.

## Memory safety

API-Sever++ has been tested for memory safety (leaks and overflows) with dynamic analysis instrumentation tools including Valgrind and GCC memory sanitizer (-fsanitize=leak and -fsanitize=address), It has passed all tests, with no leaks or warning of any sort when running a load of 2000 concurrent connections executing a variety of API requests involving database operations as well as diagnostics.

Valgrind report (GCC sanitizers only print if problems are found):

```
==3412== HEAP SUMMARY:
==3412==     in use at exit: 0 bytes in 0 blocks
==3412==   total heap usage: 4,423,921 allocs, 4,423,921 frees, 1,453,005,010 bytes allocated
==3412==
==3412== All heap blocks were freed -- no leaks are possible
==3412==
==3412== For lists of detected and suppressed errors, rerun with: -s
==3412== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

API-Server++ is a small program, code coverage is pretty complete with these tests, and most probable code paths, if not all, are executed.
Please note that in order to use dynamic analysis tools you need to compile with `-g` and `-O0`.

## Static analysis with SonarCloud

SonarCloud is the top player in C++ static analysis, performing rigorous analysis of the code to ensure compliance with [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines) as well as a database of Sonar C++ Rules, it is really strict, API-Server++ was analyzed and rewritten in order to achieve a top score with SonarCloud, this way we can provide a quality Modern C++ code-base that implements the industry-accepted best practices, and at the same time is simple and fast.

![image](https://github.com/cppservergit/apiserver/assets/126841556/8422507e-f30a-44dd-8539-1c6af62402b1)

We managed to fix all issues reported and the current code base has achieved a perfect score for all the code, no issues of any kind were detected.
