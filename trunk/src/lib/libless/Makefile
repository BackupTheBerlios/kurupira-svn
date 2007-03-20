# Makefile for the Certificateless Public Key Cryptography Module.

SRC=libless.c libless_types.c libless_quadratic.c libless_pairing.c
OBJ=${SRC:.c=.o}
INC=${SRC:.c=.h}

OPENSSL_PATH=../../../../openssl-0.9.8d

CC=gcc
CFLAGS=-O2 -Wall -pipe -pipe -std=c99 -pedantic -I $(OPENSSL_PATH)/include -I../liberror -DTIMING -DWITH_DEBUG -ggdb
LDFLAGS=-L $(OPENSSL_PATH) -lcrypto -L ../liberror -ggdb

all: $(OBJ) $(INC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -shared -o libless.so

test: $(INC)
	$(CC) $(CFLAGS) $(LDFLAGS) libless_test.c -o libless_test -L. -lless -lerror

clean:
	rm -rf *.o *.a *.so
