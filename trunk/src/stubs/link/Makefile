SRCS=link_stub.c link_stub_console.c
OBJS=${SRCS:.c=.o}

CC=gcc
CFLAGS=-Wall -O -pipe -std=c99 -pedantic -DWITH_DEBUG -DWITH_TRACE -I/usr/local/include -I../../

all: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -shared -o link_stub.so

.c.o:
	$(CC) $(CFLAGS) -c $(SRCS)

clean:
	rm -rf *.o