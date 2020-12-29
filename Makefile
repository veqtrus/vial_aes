WARNINGS := -pedantic -Wcast-align -Wpointer-arith \
	-Wbad-function-cast -Wmissing-prototypes -Wstrict-aliasing \
	-Wmissing-declarations -Winline -Wnested-externs -Wcast-qual \
	-Wshadow -Wwrite-strings -Wno-unused-parameter -Wfloat-equal
CFLAGS := -std=c99 -O2 $(WARNINGS)
CC ?= gcc

SOURCES := aes.c

.PHONY: all clean check

all: build/test build/bench

clean:
	rm -f build/* *.o

check: build/test build/bench
	build/test
	build/bench

build:
	mkdir -p build

build/%: %.c $(SOURCES) build
	$(CC) -o $@ $< $(SOURCES) $(CFLAGS)

aes.c: aes.h
