# API-Server++

Easy to build Web APIs with Modern C++ and a minimal code framework and imperative/functional programming style.

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

## Bash script to run API-Server++

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

