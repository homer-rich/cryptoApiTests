# Macros
SHELL = /bin/sh

OBJS = crlVerify.c
CFLAGS = 
CC = gcc
INCLUDES = -I/usr/include/nss -I/usr/include/nspr
LIBS = -lplc4 -lssl3 -lnss3 -lnspr4

crlVerify:
	${CC} ${OBJS} ${CFLAGS} ${INCLUDES} ${LIBS} -o $@

clean:
	-rm *.exe*
