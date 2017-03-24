CC=gcc
CFLAGS=-c -Wall

SOURCES=crypto_wrapper.c

OBJECTS=$(SOURCES:.c=.o)

all: crypto_wrapper.o

network.o :
	$(CC) $(CFLAGS) $(SOURCES) -o $@

clean:
	rm crypto_wrapper.o