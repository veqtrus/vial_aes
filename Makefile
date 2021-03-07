WARNINGS ?= -pedantic -Wall
CFLAGS ?= -std=c99 -O2 $(WARNINGS)
CC ?= gcc

SOURCES := aes.c

.PHONY: all clean check

all: bin/test bin/bench

clean:
	rm -f bin/* *.o

check: bin/test bin/bench
	bin/test
	bin/bench

bin/:
	mkdir bin

bin/%: %.c $(SOURCES) | bin/
	$(CC) -o $@ $< $(SOURCES) $(CFLAGS)

aes.c: aes.h
