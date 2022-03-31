CC=gcc
CFLAGS= -W -Wall -std=c99
SOURCES=$(wildcard *.c)
.PHONY: server client
all: server client

server:
		$(CC) $(CFLAGS) server.c -o server -L/usr/lib -lssl -lcrypto

client:
	    $(CC) $(CFLAGS) client.c -o client -L/usr/lib -lssl -lcrypto