# Makefile for the kurud daemon

SRC=kurud_console.c kurud.c kurud_main.c kurud_config.c
OBJ=${SRC:.c=.o}
INC=kurud_console.h kurud.h kurud_config.h

CC=gcc
CFLAGS=-Wall -O -pipe -ggdb -std=c99 -pedantic -DWITH_DEBUG -I/usr/local/include -I../ -I../lib/liberror -I../lib/liblog -I../../include -L/usr/local/lib -L../lib/liblog -L../lib/liberror

all: $(OBJ) $(INC)
	$(CC) $(CFLAGS) $(OBJ) -pthread -ldotconf -llog -lerror -o kurud

clean:
	rm -rf *.o *.a *.so
	
run:
	./kuru -f
	
run-trace:
	../../etrace/src/etrace kurud	