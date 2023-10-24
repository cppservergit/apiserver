SHELL=bash
DATE=$(shell printf '%(%Y%m%d)T')
CC=g++-13
CC_OPTS=-Wall -Wextra -O3 -std=c++23 -pthread -flto=4 -fno-extern-tls-init -march=x86-64 -mtune=intel
CC_LIBS=-lpq -lcurl -lcrypto -luuid -ljson-c
CC_OBJS=env.o logger.o jwt.o httputils.o email.o sql.o login.o util.o main.o

apiserver: env.o logger.o jwt.o httputils.o email.o sql.o login.o util.o main.o
	$(CC) $(CC_OPTS) $(CC_OBJS) $(CC_LIBS) -o "apiserver"

main.o: src/main.cpp src/server.h
	$(CC) $(CC_OPTS) -DCPP_BUILD_DATE=$(DATE) -c src/main.cpp

login.o: src/login.cpp src/login.h
	$(CC) $(CC_OPTS) -c src/login.cpp

sql.o: src/sql.cpp src/sql.h
	$(CC) $(CC_OPTS) -c src/sql.cpp

email.o: src/email.cpp src/email.h
	$(CC) $(CC_OPTS) -c src/email.cpp

httputils.o: src/httputils.cpp src/httputils.h
	$(CC) $(CC_OPTS) -c src/httputils.cpp

jwt.o: src/jwt.cpp src/jwt.h
	$(CC) $(CC_OPTS) -c src/jwt.cpp

util.o: src/util.cpp src/util.h
	$(CC) $(CC_OPTS) -c src/util.cpp

logger.o: src/logger.cpp src/logger.h
	$(CC) $(CC_OPTS) -c src/logger.cpp

env.o: src/env.cpp src/env.h
	$(CC) $(CC_OPTS) -c src/env.cpp

clean:
	rm env.o logger.o jwt.o sql.o login.o email.o httputils.o util.o main.o
