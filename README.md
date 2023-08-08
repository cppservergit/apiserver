# API-Server++

Easy to build Web APIs with Modern C++ and a minimal code framework using imperative/functional programming style. Fast, secure, and well-documented.

```
#include "server.h"

int main()
{
	server::register_webapi
	(
		server::webapi_path("/api/shippers/view"), 
		"List of shipping companies",
		http::verb::GET, 
		{} /* inputs */, 	
		{} /* roles */,
		[](http::request& req) 
		{
			req.response.set_body( sql::get_json_response("DB1", "select * from fn_shipper_view()") );
		}
	);

	server::start();
}
```

API-Server++ is a compact single-threaded epoll HTTP 1/1 microserver, for serving API requests only (GET/Multipart Form POST/OPTIONS), when a request arrives, the corresponding lambda will be dispatched for execution to a background thread, using the one-producer/many-consumers model. This way API-Server++ can multiplex thousands of concurrent connections with a single thread dispatching all the network-related tasks

API-Server++ was designed to be run as a container on Kubernetes, with a stateless security/session model bases on JSON web token (good for scalability), and built-in observability features for Grafana stack, but it can be run as a regular program on a terminal or as a SystemD Linux service, on production it will run behind an Ingress or Load Balancer providing TLS and Layer-7 protection.

It does use the native PostgreSQL client C API `libpq` for maximum speed, as well as `libcurl` for secure email and openssl v3 for JWT signatures.

## Requirements

The test environment is Ubuntu 22.04 with GCC 12.3, we used Canonical's Multipass VMs on Windows 10 Pro, it's a very agile toolset for this purpose.

Update Ubuntu package list:
```
sudo apt update
```

Install required packages:
```
sudo apt install g++-12 libssl-dev libpq-dev libcurl4-openssl-dev libldap-dev libldap-dev make -y --no-install-recommends
```

Optionally, you can upgrade the rest of the operating system, it may take some minutes and require a restart of the VM:
```
sudo apt upgrade -y
```

__Note__: You can use GCC-13 too if you have it installed, for Ubuntu 23.04 and greater you can use "apt install g++" instead of "g++-12". In any case, you will have to edit Makefile to change the compiler name.

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

Compile and build executable
```
cd apiserver && make
```

Expected output:
```
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/env.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/logger.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/jwt.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -c src/httputils.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -I/usr/include/postgresql -c src/sql.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -I/usr/include/postgresql -c src/login.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -I/usr/include/postgresql -DCPP_BUILD_DATE=20230807 -c src/server.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -I/usr/include/postgresql -c src/main.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel env.o logger.o jwt.o httputils.o sql.o login.o server.o main.o -lpq -lcurl -lcrypto -o "apiserver"
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
# default paths
export CPP_MAIL_TEMPLATES="/var/mail"
export CPP_BLOB_STORAGE="/var/blobs"
# JWT config
export CPP_JWT_PASSWORD="basica"
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
{"source":"server","level":"info","msg":"registering built-in diagnostic and security services..."}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/ping"}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/version"}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/sysinfo"}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/metrics"}
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/login"}
{"source":"env","level":"info","msg":"port: 8080"}
{"source":"env","level":"info","msg":"pool size: 4"}
{"source":"env","level":"info","msg":"login log: 1"}
{"source":"env","level":"info","msg":"http log: 1"}
{"source":"server","level":"info","msg":"Pod: test PID: 9332 starting microserver-pgsql v1.0.0-20230807"}
{"source":"server","level":"info","msg":"hardware threads: 4 GCC: 12.3.0"}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"139977899996736"}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"139977908389440"}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"139977891604032"}
{"source":"epoll","level":"info","msg":"starting epoll FD: 4"}
{"source":"epoll","level":"info","msg":"listen socket FD: 5 port: 8080"}
{"source":"pool","level":"info","msg":"starting worker thread","thread":"139977816012352"}
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
curl localhost:8080/api/login -F "login=mcordova" -F "password=basica"
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

Add this code right above server:start():
```
	server::register_webapi
	(
		server::webapi_path("/api/shippers/view"), 
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
With one line of code we define a new API, with some metadata including a description, the HTTP method supported, input rules validation if any, authorized roles if any and most important, a lambda function with the code implementing the API, a one-liner in this case, thanks to the high-level abstractions of API-Server++.

The whole program should look like this:
```
#include "server.h"

int main()
{
        server::register_webapi
        (
                server::webapi_path("/api/shippers/view"),
                "List of shipping companies",
                http::verb::GET,
                {} /* inputs */,
                {} /* roles */,
                [](http::request& req)
                {
                        req.response.set_body( sql::get_json_response("DB1", "select * from fn_shipper_view()") );
                }
        );

        server::start();
}
```

Now recompile, only the main.cpp module will be recompiled and the program relinked with the object files, it's a quick operation:
```
make
```

Expected output:
```
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel -I/usr/include/postgresql -c src/main.cpp
g++-12 -Wno-unused-parameter -Wpedantic -Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel env.o logger.o jwt.o httputils.o sql.o login.o server.o main.o -lpq -lcurl -lcrypto -o "apiserver"
```

Now run the server again:
```
./run
```

Now starting the log output (2nd line) you should see this line:
```
{"source":"server","level":"info","msg":"registered WebAPI for path: /api/shippers/view"}
```

Now that the API-Server++ is running again and your API has been published, let's test it with CURL in the 2nd terminal we used before with curl, first, we need to login to obtain a [JWT token](https://jwt.io/introduction), otherwise, any attempt to invoke your API will be rejected with HTTP status code 401 (required login error).

```
curl localhost:8080/api/login -F "login=mcordova" -F "password=basica"
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

The token gets validated by API-Server++ before executing your lambda, it has a default duration of 10 minutes and it can be configured via environment variable, in a Kubernetes-friendly way, in any case, authentication and authorization are transparent to your API and always enforced. All registered APIs are secure by default unless explicitly disabled, in this case a clear message will be recorded in the logs when registering the API:
```
{"source":"server","level":"info","msg":"registered (insecure) WebAPI for path: /api/ping"}
```

It's good to know how to test you APIs the "manual way" using CURL, but when passing the security token is required, it becomes a bit tedious, we can use a very simple HTML page with a bit of modern Javascript to automate API testing including security. For this exercise's sake we will assume that you are in your desktop environment, where you can use a browser to connect to the VM running your API, API-Server++ must be running on you Linux VM. 
Open the browser and navigate to (PLEASE use your VM IP address or the hostname if you are using Canonical's Multipass VMs on Windows 10 Pro):
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
		loginForm.append("login", "mcordova");
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

		//call some builtin diagnostic APIs
		call_api("/api/version", function(json) {
					console.table(json.data); 
				});
	
		call_api("/api/sysinfo", function(json) {
					console.table(json.data); 
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

You can configure the log to be less verbose by changing the environment variables in the `run` script, which is recommended for production because it has overhead and the Ingress/Load Balancer will produce entries like these.
```
export CPP_LOGIN_LOG=0
export CPP_HTTP_LOG=0
```
__Note__: warning and error log entries cannot be disabled.

