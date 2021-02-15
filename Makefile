WARNINGS ?= -pedantic -Wall
CFLAGS ?= -std=c99 -O2 $(WARNINGS)
CC ?= gcc

SOURCES := aes.c

.PHONY: all clean check

all: build/test build/bench

clean:
	rm -f build/* *.o

check: build/test build/bench
	build/test
	build/bench

build/:
	mkdir build

build/%: %.c $(SOURCES) build/
	$(CC) -o $@ $< $(SOURCES) $(CFLAGS)

aes.c: aes.h
