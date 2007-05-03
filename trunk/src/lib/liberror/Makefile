# Makefile for liberror

SRC=liberror.c
OBJ=${SRC:.c=.o}

CC=gcc
CFLAGS=-Wall -O2 -pipe -std=c99 -pedantic -fPIC -ggdb -DWITH_DEBUG -I/usr/local/include -I../../ -L/usr/local/lib

all: $(OBJ) liberror.h
	$(CC) $(CFLAGS) $(OBJ) -shared -o liberror.so

clean:
	rm -rf *.o *.a *.so
