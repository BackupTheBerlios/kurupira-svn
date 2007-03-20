/*
 * Copyright (C) 2004 by
 * - Diego "iamscared" Aranha <iamscared[at]users.sourceforge.net> &
 * - Edans "snade" Flavius <snade[at]users.sourceforge.net>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
 
/**
 * @file lnp_store.h Procedures used to manage key store items.
 * @ingroup lnp
 */

#ifndef _LNP_STORE_H_
#define _LNP_STORE_H_

#include <netinet/in.h>

#include <pthread.h>

#include <libfreedom/layer_net.h>
#include <util/util_crypto.h>

#include "lnp_packets.h"

/**
 * Time atom used to handle time intervals (in milliseconds).
 */
#define LNP_TIME_TICK					500

/**
 * Number of time ticks per second.
 */
#define LNP_TIME_TICKS_PER_SECOND		(1000/LNP_TIME_TICK)

/**
 * 
 */
#define KEY_TABLE_SIZE	0x10

/**
 * 
 */
#define NULL_SLOT (-1)

/*
 * 
 */
#define USED_SLOT (-2)

/**
 * 
 */
enum lnp_handshake_states {
	/** */
	LNP_HANDSHAKE_CLOSED,	
	/** */
	LNP_HANDSHAKE_CONNECTING,
	/** */
	LNP_HANDSHAKE_BEING_CONNECTED,
	/** */
	LNP_HANDSHAKE_EXCHANGING_KEYS,
	/** */
	LNP_HANDSHAKE_CONNECTED
};

/**
 * Data type that stores the information associated with a key store entry.
 */
typedef struct {
	/** Number of packets sent in connection. */
	int packets_sent;
	/** Number of packets received in connection. */
	int packets_received;
	/** Usage counter to track if this entry is being used by the transport
	 * layer */
	int counter;
	/** Current timeout in number of LNP_TIME_TICKs. */
	int timeout;
	/** */
	int handshake_state;
	/** Code of the last error occurred in session. */
	int error;
	/** Encryption function used. */
	util_cipher_function_t *cipher;
	/** Hash function used. */
	util_hash_function_t *hash;
	/** MAC function used. */
	util_mac_function_t *mac;
	/** Key to decrypt incoming traffic. */
	u_char *cipher_in_key;
	/** Initialization vector of decryption. */
	u_char *cipher_in_iv;
	/** Key to encrypt outgoing traffic. */
	u_char *cipher_out_key;
	/** Initialization vector of encryption. */
	u_char *cipher_out_iv;
	/** Key to verify MAC of incoming traffic. */
	u_char *mac_in_key;
	/** Key to generate MAC of outgoing traffic. */
	u_char *mac_out_key;
	/** Next free slot. */
	int next_free_slot;
	/** */
	u_char k_in[LNP_K_LENGTH];
	/** */
	u_char k_out[LNP_K_LENGTH];
	/** */
	u_char encrypted_k_in[LNP_K_LENGTH];
	/** */
	u_char encrypted_k_out[LNP_K_LENGTH];
	/** */
	u_char public_key[LNP_PUBLIC_KEY_LENGTH];
	/** */
	/*pthread_cond_t handshake_condition;*/
	/** */
	/*pthread_mutex_t handshake_mutex;*/
} lnp_key_entry_t;

/**
 * Array that stores the information associated with each host known by the
 * network layer. Access to this structure must be controlled my mutexes.
 */
extern lnp_key_entry_t lnp_key_store[KEY_TABLE_SIZE];

/**
 * Initializes the data structures for the key store.
 * 
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_key_store_initialize();

/**
 * Frees the memory associated with the key store.
 */
void lnp_key_store_finalize();

/**
 * 
 */
int lnp_key_store_new();

/**
 * 
 */
void lnp_key_store_delete(int key_entry_index);

/**
 * 
 */
int lnp_set_cipher_in_key(int index, u_char *key);
/**
 * 
 */
int lnp_set_cipher_in_iv(int index, u_char *iv);
/**
 * 
 */
int lnp_set_cipher_out_key(int index, u_char *key);
/**
 * 
 */
int lnp_set_cipher_out_iv(int index, u_char *iv);
/**
 * 
 */
int lnp_set_mac_in_key(int index, u_char *key);
/**
 * 
 */
int lnp_set_mac_out_key(int index, u_char *key);


#endif /* !_LNP_STORE_H_ */
