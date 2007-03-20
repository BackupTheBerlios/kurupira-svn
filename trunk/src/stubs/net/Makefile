SRCS=net_stub.c net_stub_console.c
OBJS=${SRCS:.c=.o}

CC=gcc
CFLAGS=-Wall -O -pipe -std=c99 -pedantic -DWITH_DEBUG -DWITH_TRACE -I/usr/local/include -I../../

all: $(OBJS) net_stub.h
	$(CC) $(CFLAGS) $(OBJS) -shared -o net_stub.so

.c.o:
	$(CC) $(CFLAGS) -c $(SRCS)

clean:
	rm -rf *.o