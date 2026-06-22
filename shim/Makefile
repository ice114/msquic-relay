# 端侧网关 shim — portable POSIX UDP proxy (macOS + Linux).
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
INCLUDE  = -I../include

shim: shim.c ../include/tunnel_protocol.h
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ shim.c

clean:
	rm -f shim

.PHONY: clean
