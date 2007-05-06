# Makefile for the Certificateless Public Key Cryptography Module.

SRC=libless.c libless_types.c libless_quadratic.c libless_pairing.c libless_util.c libless_signature.c libless_encryption.c libless_aggregate.c
OBJ=${SRC:.c=.o}
INC=${SRC:.c=.h}

OPENSSL_PATH=/usr

CC=gcc
CFLAGS=-Wall -pipe -fPIC -std=c99 -pedantic -I $(OPENSSL_PATH)/include -I../liberror -DWITH_TIMING -DWITH_DEBUG -ggdb -DWITH_CHECKING -D_POSIX_C_SOURCE=199309L
LDFLAGS=-L $(OPENSSL_PATH) -lcrypto -L ../liberror -ggdb

all: $(OBJ) $(INC) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -shared -o libless.so

test: $(INC) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) libless_test_signature.c -o libless_test_signature -L. -lless -lerror -lrt
	$(CC) $(CFLAGS) $(LDFLAGS) libless_test_encryption.c -o libless_test_encryption -L. -lless -lerror -lrt
	$(CC) $(CFLAGS) $(LDFLAGS) libless_test_aggregate.c -o libless_test_aggregate -L. -lless -lerror -lrt

clean:
	rm -rf *.o *.a *.so
