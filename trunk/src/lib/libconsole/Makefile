SRCS=libconsole.c

CC=gcc
CFLAGS=-Wall -O -ggdb -pipe -std=c99 -pedantic -DWITH_DEBUG -I/usr/local/include -I../../ -L/usr/local/lib

all: $(OBJS)
	$(CC) $(CFLAGS) $(SRCS) -c -o libconsole.a

clean:
	rm -rf *.o *.a *.so