SRCS=console_core.c console_main.c
OBJS=${SRCS:.c=.o}

CC=gcc
CFLAGS=-Wall -O -ggdb -pipe -std=c99 -pedantic -DWITH_DEBUG -I/usr/local/include -I../ -L../libs/libconsole

all: $(OBJS) console_core.h console.h
	$(CC) $(CFLAGS) $(OBJS) -lreadline -lconsole -o console 

.c.o: console_core.h console.h
	$(CC) $(CFLAGS) -c $(SRCS)

clean:
	rm -rf *.o