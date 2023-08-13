SHELL=bash
DATE=$(shell printf '%(%Y%m%d)T')
CC=g++-12
CC_OPTS=-Wall -Wextra -O3 -std=c++23 -pthread -flto=6 -fno-extern-tls-init -march=native -mtune=intel
CC_LIBS=-lpq -lcurl -lcrypto
CC_OBJS=env.o logger.o jwt.o httputils.o sql.o login.o server.o main.o

apiserver: env.o logger.o jwt.o httputils.o sql.o login.o server.o main.o
	$(CC) $(CC_OPTS) $(CC_OBJS) $(CC_LIBS) -o "apiserver"

main.o: src/main.cpp
	$(CC) $(CC_OPTS) -I/usr/include/postgresql -c src/main.cpp

server.o: src/server.cpp src/server.h
	$(CC) $(CC_OPTS) -I/usr/include/postgresql -DCPP_BUILD_DATE=$(DATE) -c src/server.cpp

login.o: src/login.cpp src/login.h
	$(CC) $(CC_OPTS) -I/usr/include/postgresql -c src/login.cpp

sql.o: src/sql.cpp src/sql.h
	$(CC) $(CC_OPTS) -I/usr/include/postgresql -c src/sql.cpp

httputils.o: src/httputils.cpp src/httputils.h
	$(CC) $(CC_OPTS) -c src/httputils.cpp

jwt.o: src/jwt.cpp src/jwt.h
	$(CC) $(CC_OPTS) -c src/jwt.cpp

logger.o: src/logger.cpp src/logger.h
	$(CC) $(CC_OPTS) -c src/logger.cpp

env.o: src/env.cpp src/env.h
	$(CC) $(CC_OPTS) -c src/env.cpp

clean:
	rm env.o logger.o jwt.o sql.o login.o httputils.o server.o main.o
