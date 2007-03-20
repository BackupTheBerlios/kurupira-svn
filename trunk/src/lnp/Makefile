SRCS=lnp_core.c lnp_config.c lnp_collision_table.c lnp_history_table.c   lnp_routing_policy.c  lnp_id.c  lnp_routing_table.c lnp_store.c lnp_threads.c lnp_queue.c lnp_console.c lnp_link.c lnp_data.c lnp_clocks.c lnp_handshake.c
OBJS=${SRCS:.c=.o}
LIBS=-L/usr/local/lib -lcrypto -ldotconf -pthread -L../libs/liblog -llog
H=lnp.h lnp_history_table.h lnp_routing_policy.h lnp_collision_table.h lnp_id.h lnp_routing_table.h lnp_config.h lnp_packets.h lnp_store.h lnp_threads.h lnp_queue.h lnp_link.h lnp_clocks.h lnp_handshake.h
CC=gcc
CFLAGS=-Wall -O -pipe -ggdb -std=c99 -pedantic -DWITH_DEBUG -DWITH_TRACE -I/usr/local/include -I.. 

all: $(OBJS) lnp_config.h ../util/util_data.h ../util/util_crypto.h
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) ../util/*.o -shared -o lnp.so

.c.o:
	$(CC) $(CFLAGS) -c $(SRCS)

clean:
	rm -rf *.o *.so