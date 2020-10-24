WARNINGS := -pedantic -Wcast-align -Wpointer-arith \
	-Wbad-function-cast -Wmissing-prototypes -Wstrict-aliasing \
	-Wmissing-declarations -Winline -Wnested-externs -Wcast-qual \
	-Wshadow -Wwrite-strings -Wno-unused-parameter -Wfloat-equal
CFLAGS := -std=c99 -O2 $(WARNINGS)
CC ?= gcc

SOURCES := aes.c

.PHONY: all clean check

all: test

clean:
	rm -f test *.o

check: test
	./test

test: test.c $(SOURCES)
	$(CC) -o $@ $^ $(CFLAGS)

aes.c: aes.h
