# Makefile for liblog

SRC=liblog.c
OBJ=${SRC:.c=.o}

CC=gcc
CFLAGS=-Wall -O2 -pipe -std=c99 -pedantic -ggdb -DWITH_DEBUG -I/usr/local/include -I../../ -L/usr/local/lib

all: $(OBJ) liblog.h
	$(CC) $(CFLAGS) $(OBJ) -shared -o liblog.so

clean:
	rm -rf *.o *.a *.so