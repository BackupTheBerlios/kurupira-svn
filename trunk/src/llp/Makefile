SRCS=llp_core.c llp_queue.c llp_info.c llp_threads.c llp_socket.c llp_sessions.c llp_packets.c llp_nodes.c llp_handshake.c llp_dh.c llp_data.c llp_console.c llp_config.c
OBJS=${SRCS:.c=.o}
LIBS=-L/usr/local/lib -lcrypto -ldotconf -pthread -L../libs/liblog -llog

CC=gcc
CFLAGS=-Wall -O -pipe -ggdb -std=c99 -pedantic -DWITH_DEBUG -DWITH_TRACE -I/usr/local/include -I.. 

all: $(OBJS) llp_config.h ../util/util_data.h ../util/util_crypto.h llp_sessions.h llp_packets.h llp_handshake.h llp_dh.h llp_sessions.h
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) ../util/*.o -shared -o llp.so

.c.o:
	$(CC) $(CFLAGS) -c $(SRCS)

clean:
	rm -rf *.o *.so