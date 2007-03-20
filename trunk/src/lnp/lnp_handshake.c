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
 * @file lnp_handshake.c Implementation of functions used to establish a new
 * 		connection.
 * @ingroup lnp
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

#include <libfreedom/types.h>
#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>
#include <util/util.h>
#include <util/util_data.h>
#include <util/util_crypto.h>
#include <util/util_keys.h>

#include "lnp_handshake.h"
#include "lnp_routing_table.h"
#include "lnp_packets.h"
#include "lnp_config.h"
#include "lnp_id.h"
#include "lnp_link.h"
#include "lnp_store.h"
#include "lnp.h"

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * 
 */
int create_keys(int index);

/*
 * Checks if the remote and local protocol versions are compatible.
 */
static int verify_versions(u_char remote_major, u_char remote_minor);

/**
 * Sends a LNP_PUBLIC_KEY_REQUEST packet.
 * 
 * @param id ID to connect.
 * @port port used by the peer being connected.
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
static inline int send_public_key_request(net_id_t id, u_char mode);

/*
 * Sends a LNP_PUBLIC_KEY_RESPONSE_OK packet.
 */
static inline int send_public_key_response(net_id_t id, int store_entry_index);

/*
 * Sends a LNP_KEY_EXCHANGE packet.
 */
static inline int send_key_exchange(net_id_t id, int store_entry_index);

/*
 * Sends a LNP_KEY_EXCHANGE_OK packet.
 */
static inline int send_key_exchange_ok(net_id_t id, int store_entry_index);

/*
 * Reads the contents of a LNP_PUBLIC_KEY_REQUEST into packet.
 */
int parse_public_key_request(lnp_public_key_request_p *packet,
		u_char *packet_data, int packet_size);
		
/*
 * Reads the contents of a LNP_UBLIC_KEY_RESPONSE into packet.
 */
static inline int parse_public_key_response(lnp_public_key_response_p *packet,
		u_char *packet_data, int packet_length);
		
/*
 * Reads the contents of a LNP_KEY_EXCHANGE into packet.
 */
static inline int parse_key_exchange(lnp_key_exchange_p *packet,
		u_char *packet_data, int packet_length);
		
/*
 * Reads the contents of a LNP_KEY_EXCHANGE_OK into packet.
 */
static inline int parse_key_exchange_ok(lnp_key_exchange_ok_p *packet,
		u_char *packet_data, int packet_length);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int lnp_handle_public_key_request(lnp_packet_p *packet, int content_length) {
	lnp_public_key_request_p public_key_request;
	int routing_entry_index;
	int store_entry_index;

	if (parse_public_key_request(&public_key_request,
			packet->content, content_length) == LNP_ERROR) {
		liblog_debug(LAYER_NET, "packet format corrupted.");	
		return LNP_ERROR;
	} 
	liblog_debug(LAYER_NET, "packet successfuly parsed.");	
	
	/* Verifying protocol versions. */
	if (verify_versions(public_key_request.major_version,
			public_key_request.minor_version) == LNP_ERROR) {
		return LNP_ERROR;
	}
	
	/* lock routing entry */
	routing_entry_index = lnp_routing_entry_lock(packet->source);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		//TODO
	}

	if (routing_table[routing_entry_index].store_index == NULL_SLOT) {
		store_entry_index = lnp_key_store_new();
		routing_table[routing_entry_index].store_index = store_entry_index;
	}
	store_entry_index = routing_table[routing_entry_index].store_index;

	/* unlock routing entry */
	/*lnp_routing_entry_unlock(routing_entry_index);*/

	memcpy(lnp_key_store[store_entry_index].public_key,
			public_key_request.public_key, LNP_PUBLIC_KEY_LENGTH);
			
	/* Generating k parameter. */
	if (util_rand_bytes(lnp_key_store[store_entry_index].k_out, LNP_K_LENGTH)
			== UTIL_ERROR) {
		liblog_error(LAYER_NET, "error generating k parameter.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;		
	};
	liblog_debug(LAYER_NET, "parameter k generated.");
	
	lnp_key_store[store_entry_index].handshake_state =
			LNP_HANDSHAKE_BEING_CONNECTED;

	/* Send request packet. */
	if (send_public_key_response(packet->source, store_entry_index)
			== LNP_ERROR) {
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}

	lnp_routing_entry_unlock(routing_entry_index);



	return LNP_OK;
}
/******************************************************************************/
int lnp_handle_public_key_response(lnp_packet_p *packet, int content_length) {
	lnp_public_key_response_p public_key_response;
	int routing_entry_index;
	int store_entry_index;

	/* Reading packet */
	if (parse_public_key_response(&public_key_response,
			packet->content, content_length) == LNP_ERROR) {
		liblog_debug(LAYER_NET, "packet format corrupted.");	
		return LNP_ERROR;
	} 
	liblog_debug(LAYER_NET, "packet successfuly parsed.");	

	/* lock routing entry */
	routing_entry_index = lnp_routing_entry_lock(packet->source);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		//TODO
	}

	store_entry_index = routing_table[routing_entry_index].store_index;
	
	if (lnp_key_store[store_entry_index].handshake_state !=
			LNP_HANDSHAKE_CONNECTING) {
		liblog_info(LAYER_NET, "public_key_response dropped: "
				"state must be LNP_HANDSHAKE_CONNECTING.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	
	/* Generating k parameter. */
	if (util_rand_bytes(lnp_key_store[store_entry_index].k_out, LNP_K_LENGTH)
			== UTIL_ERROR) {
		liblog_error(LAYER_NET, "error generating k parameter.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;		
	};
	liblog_debug(LAYER_NET, "parameter k generated.");

	memcpy(lnp_key_store[store_entry_index].public_key,
			public_key_response.public_key, LNP_PUBLIC_KEY_LENGTH);	
	//TODO cifrar
	memcpy(lnp_key_store[store_entry_index].k_in,
			public_key_response.encrypted_k, LNP_K_LENGTH);	
			
	/* Send key exchange packet. */
	if (send_key_exchange(packet->source, store_entry_index) == LNP_ERROR) {
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}

	lnp_key_store[store_entry_index].handshake_state =
			LNP_HANDSHAKE_EXCHANGING_KEYS;

	lnp_routing_entry_unlock(routing_entry_index);

	return LNP_OK;
}
/******************************************************************************/
int lnp_handle_key_exchange(lnp_packet_p *packet, int content_length) {
	lnp_key_exchange_p key_exchange;
	int routing_entry_index;
	int store_entry_index;
	
	/* Reading packet */
	if (parse_key_exchange(&key_exchange,
			packet->content, content_length) == LNP_ERROR) {
		liblog_debug(LAYER_NET, "packet format corrupted.");	
		return LNP_ERROR;
	} 
	liblog_debug(LAYER_NET, "packet successfuly parsed.");	
	
	/* lock routing entry */
	routing_entry_index = lnp_routing_entry_lock(packet->source);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		//TODO
	}

	store_entry_index = routing_table[routing_entry_index].store_index;
	
	if (lnp_key_store[store_entry_index].handshake_state !=
			LNP_HANDSHAKE_BEING_CONNECTED) {
		liblog_info(LAYER_NET, "public_key_exchange dropped: "
				"state must be LNP_HANDSHAKE_BEING_CONNECTED.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	
	lnp_key_store[store_entry_index].cipher = 
			lnp_cipher_search(key_exchange.ciphers);
	lnp_key_store[store_entry_index].hash =
			lnp_hash_search(key_exchange.hashes);
	lnp_key_store[store_entry_index].mac =
			lnp_mac_search(key_exchange.macs);
			
	/* Functions received don't support even the defaults. */
	if (lnp_key_store[store_entry_index].cipher == NULL ||
			lnp_key_store[store_entry_index].hash == NULL ||
			lnp_key_store[store_entry_index].mac == NULL) {
		liblog_error(LAYER_NET,
				"received functions not supported, packet dropped.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	liblog_debug(LAYER_NET, "received functions are supported.");
	
	// TODO decifrar
	if (memcmp(lnp_key_store[store_entry_index].k_out,
			key_exchange.encrypted_k_1, LNP_K_LENGTH) != 0) {
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	liblog_debug(LAYER_NET, "parameter k authenticated.");
	
	// TODO decifrar
	memcpy(lnp_key_store[store_entry_index].k_in,
			key_exchange.encrypted_k_2, LNP_K_LENGTH);

	/* Create all the keys. */
	if (create_keys(store_entry_index) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating session keys.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;						
	};
	
	if (send_key_exchange_ok(packet->source, store_entry_index) == LNP_ERROR) {
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	
	lnp_key_store[store_entry_index].handshake_state =
			LNP_HANDSHAKE_CONNECTED;
	
	/*pthread_cond_broadcast(
			&lnp_key_store[store_entry_index].handshake_condition);*/
	/*lnp_routing_entry_signal(routing_entry_index);*/

	lnp_routing_entry_unlock(routing_entry_index);

	return LNP_OK;
}
/******************************************************************************/
int lnp_handle_key_exchange_ok(lnp_packet_p *packet, int content_length) {
	lnp_key_exchange_ok_p key_exchange_ok;
	int routing_entry_index;
	int store_entry_index;
	
	/* Reading packet */
	if (parse_key_exchange_ok(&key_exchange_ok,
			packet->content, content_length) == LNP_ERROR) {
		liblog_debug(LAYER_NET, "packet format corrupted.");	
		return LNP_ERROR;
	} 
	liblog_debug(LAYER_NET, "packet successfuly parsed.");	
	
	/* lock routing entry */
	routing_entry_index = lnp_routing_entry_lock(packet->source);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		//TODO
	}

	store_entry_index = routing_table[routing_entry_index].store_index;
	
	if (lnp_key_store[store_entry_index].handshake_state !=
			LNP_HANDSHAKE_EXCHANGING_KEYS) {
		liblog_info(LAYER_NET, "public_key_exchange_ok dropped: "
				"state must be LNP_HANDSHAKE_EXCHANGING_KEYS.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	
	lnp_key_store[store_entry_index].cipher = 
			lnp_cipher_search(key_exchange_ok.cipher);
	lnp_key_store[store_entry_index].hash =
			lnp_hash_search(key_exchange_ok.hash);
	lnp_key_store[store_entry_index].mac =
			lnp_mac_search(key_exchange_ok.mac);
			
	/* Functions received don't support even the defaults. */
	if (lnp_key_store[store_entry_index].cipher == NULL ||
			lnp_key_store[store_entry_index].hash == NULL ||
			lnp_key_store[store_entry_index].mac == NULL) {
		liblog_error(LAYER_NET,
				"received functions not supported, packet dropped.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	liblog_debug(LAYER_NET, "received functions are supported.");
	
	// TODO decifrar
	if (memcmp(lnp_key_store[store_entry_index].k_out,
			key_exchange_ok.encrypted_k, LNP_K_LENGTH) != 0) {
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	
	/* Create all the keys. */
	if (create_keys(store_entry_index) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating keys.");
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;						
	};
	
	lnp_key_store[store_entry_index].handshake_state =
			LNP_HANDSHAKE_CONNECTED;

	lnp_routing_entry_signal(routing_entry_index);

	lnp_routing_entry_unlock(routing_entry_index);

	return LNP_OK;

}
/******************************************************************************/
int lnp_connect(net_id_t id) {
	int routing_entry_index;
	int store_entry_index;
	int return_value;
	u_char transmission_mode;
	
	routing_entry_index = lnp_routing_entry_lock(id);
	transmission_mode = LNP_BROADCAST;
	if (routing_entry_index != LNP_LOOKUP_ERROR) {
		transmission_mode = LNP_UNICAST;
	} else {
		lnp_add_id(id);
		routing_entry_index = lnp_routing_entry_lock(id);
		if (routing_entry_index == LNP_LOOKUP_ERROR) {
			return LNP_ERROR;
		}
	}
	
	if (routing_table[routing_entry_index].store_index == NULL_SLOT) {
		store_entry_index = lnp_key_store_new();
		routing_table[routing_entry_index].store_index = store_entry_index;
	}
	
	store_entry_index = routing_table[routing_entry_index].store_index;
	
	lnp_key_store[store_entry_index].handshake_state = LNP_HANDSHAKE_CONNECTING;
			
	if (send_public_key_request(id, transmission_mode)
			== LNP_ERROR) {
		lnp_routing_entry_unlock(routing_entry_index);
		return LNP_ERROR;
	}
	
	lnp_routing_entry_condwait(routing_entry_index, 
			(LNP_TIME_TICK*LNP_T_HANDSHAKE));
	
	return_value = (lnp_key_store[store_entry_index].handshake_state ==
			LNP_HANDSHAKE_CONNECTED ? LNP_OK : LNP_ERROR);
	if (return_value == LNP_ERROR) {
		lnp_key_store[store_entry_index].handshake_state = LNP_HANDSHAKE_CLOSED;		
	}
	
	lnp_routing_entry_unlock(routing_entry_index);
		
	return return_value;
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int create_keys(int index) {
	u_char *cipher_key;
	u_char *cipher_iv;
	u_char *mac_key;
	u_char k_in[2 * LNP_K_LENGTH];
	u_char k_out[2 * LNP_K_LENGTH];
	u_char public_key[LNP_PUBLIC_KEY_LENGTH];
	int public_key_length;
	
	liblog_debug(LAYER_NET, "generating session keys.");
	
	public_key_length =
			lnp_get_public_key(public_key, LNP_PUBLIC_KEY_LENGTH);

	/* Allocating memory for temporary key containers. */
	//TODO pegar do store
	cipher_key = (u_char *)malloc(lnp_key_store[index].cipher->key_length);
	cipher_iv = (u_char *)malloc(lnp_key_store[index].cipher->iv_length);
	mac_key = (u_char *)malloc(lnp_key_store[index].mac->key_length);
	if (cipher_key == NULL || cipher_iv == NULL || mac_key == NULL) {
		free(cipher_key);
		free(cipher_iv);
		free(mac_key);
		liblog_fatal(LAYER_NET, "error in malloc: %s", strerror(errno));
		return LNP_ERROR;
	}
	liblog_debug(LAYER_NET, "memory allocated for session keys.");
	
	memcpy(k_in, lnp_key_store[index].k_in, LNP_K_LENGTH);
	memcpy(&k_in[LNP_K_LENGTH], lnp_key_store[index].k_out,
			LNP_K_LENGTH);
	memcpy(k_out, lnp_key_store[index].k_out, LNP_K_LENGTH);
	memcpy(&k_out[LNP_K_LENGTH], lnp_key_store[index].k_in,
			LNP_K_LENGTH);

	if (util_create_key(
			cipher_key,
			lnp_key_store[index].cipher->key_length,
			lnp_key_store[index].public_key,
			k_in,
			2 * LNP_K_LENGTH,
			"key",
			lnp_key_store[index].hash) == LNP_ERROR
				|| lnp_set_cipher_in_key(index, cipher_key) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating cipher_in_key.");
		free(cipher_key);
		free(cipher_iv);
		free(mac_key);
		return LNP_ERROR;
	}

	if (util_create_key(
			cipher_key, 
			lnp_key_store[index].cipher->key_length,
			public_key,
			k_out,
			2 * LNP_K_LENGTH,
			"key",
			lnp_key_store[index].hash) == LNP_ERROR
				|| lnp_set_cipher_out_key(index, cipher_key) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating cipher_out_key.");
		free(cipher_key);
		free(cipher_iv);
		free(mac_key);
		return LNP_ERROR;
	}
	
	if (util_create_key(
			cipher_iv,
			lnp_key_store[index].cipher->iv_length,
			lnp_key_store[index].public_key,
			k_in,
			2 * LNP_K_LENGTH,
			"iv",
			lnp_key_store[index].hash) == LNP_ERROR
				|| lnp_set_cipher_in_iv(index, cipher_iv) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating cipher_in_iv.");
		free(cipher_key);
		free(cipher_iv);
		free(mac_key);
		return LNP_ERROR;
	}
	
	if (util_create_key(
			cipher_iv, 
			lnp_key_store[index].cipher->iv_length,
			public_key,
			k_out,
			2 * LNP_K_LENGTH,
			"iv",
			lnp_key_store[index].hash) == LNP_ERROR
				|| lnp_set_cipher_out_iv(index, cipher_iv) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating cipher_out_iv.");
		free(cipher_key);
		free(cipher_iv);
		free(mac_key);
		return LNP_ERROR;
	}

	if (util_create_key(
			mac_key, 
			lnp_key_store[index].mac->key_length,
			lnp_key_store[index].public_key,
			k_in,
			2 * LNP_K_LENGTH,
			"mac",
			lnp_key_store[index].hash) == LNP_ERROR
				|| lnp_set_mac_in_key(index, mac_key) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating mac_in_key.");
		free(cipher_key);
		free(cipher_iv);
		free(mac_key);
		return LNP_ERROR;
	}
	
	if (util_create_key(
			mac_key, 
			lnp_key_store[index].mac->key_length,
			public_key,
			k_out,
			2 * LNP_K_LENGTH,
			"mac",
			lnp_key_store[index].hash) == LNP_ERROR
				|| lnp_set_mac_out_key(index, mac_key) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating mac_out_key.");
		free(cipher_key);
		free(cipher_iv);
		free(mac_key);
		return LNP_ERROR;
	}
	
	liblog_error(LAYER_NET, "keys generated.");

	free(cipher_key);
	free(cipher_iv);
	free(mac_key);
	return LNP_OK;
}
/******************************************************************************/
int verify_versions(u_char remote_major, u_char remote_minor) {
	/*
	 * Boolean that controls if a log message informing about a new LNP version 
	 * was found when a connection was being established with some host.
	 */
	static int new_version_found = 0;
	
	/* Testing protocol major version implemented by remote peer. */
	if (remote_major != LNP_MAJOR_VERSION) {
		liblog_warn(LAYER_NET,
				"incompatible protocol versions: local: %d.%d; remote: %d.%d",
				LNP_MAJOR_VERSION, LNP_MINOR_VERSION, 
				remote_major, remote_minor);
		if (remote_major > LNP_MAJOR_VERSION) {
			liblog_info(LAYER_NET,
					"remote peer uses version %d.%d, upgrade mandatory.",
				remote_major, remote_minor);
				new_version_found = 1;			
		}
		return LNP_ERROR;
	}
	/* Comparing minor versions. */
	if (remote_minor > LNP_MINOR_VERSION &&	!new_version_found) {
		liblog_info(LAYER_NET,
				"remote peer uses version %d.%d, upgrade recommended.",
				remote_major, remote_minor);
		new_version_found = 1;
	}
	liblog_debug(LAYER_NET, "protocol versions verified.");
	
	return LNP_OK;
}
/******************************************************************************/
int send_public_key_request(net_id_t id, u_char mode) {
	int offset;
	u_char ttl = 0;
	u_char flags = 0;
	u_char packet[LNP_PUBLIC_KEY_REQUEST_MAX_LENGTH];
	u_char public_key[LNP_PUBLIC_KEY_LENGTH];
	int public_key_length;
		
	/* Constructing public key request packet */
	offset = 0;
	public_key_length =
			lnp_get_public_key(public_key, LNP_PUBLIC_KEY_LENGTH);
	util_join_byte  (packet, &offset, LNP_PUBLIC_KEY_REQUEST);
	util_join_byte  (packet, &offset, ttl);
	util_join_bytes (packet, &offset, (u_char *)my_id, NET_ID_LENGTH);
	util_join_bytes (packet, &offset, (u_char *)id, NET_ID_LENGTH);
	util_join_byte  (packet, &offset, flags);
	util_join_byte  (packet, &offset, LNP_MAJOR_VERSION);
	util_join_byte  (packet, &offset, LNP_MINOR_VERSION);
	util_join_byte  (packet, &offset, mode);
	util_join_mpint (packet, &offset, public_key);

	liblog_debug(LAYER_NET, "packet constructed.");
	
	/* Sending packet. */
	if (lnp_link_write(packet, offset) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error sending packet.");
		return LNP_ERROR;
	}
	liblog_debug(LAYER_NET, "packet sent.");
	
	return LNP_OK;
}
/******************************************************************************/
int send_public_key_response(net_id_t id, int store_entry_index) {
	int offset;
	u_char ttl = 0;
	u_char flags = 0;
	u_char public_key[LNP_PUBLIC_KEY_LENGTH];
	u_char packet[LNP_PUBLIC_KEY_RESPONSE_MAX_LENGTH];
	int public_key_length;

	/* Constructing public key request acknowledgement packet. */
	offset = 0;
	public_key_length = 
			lnp_get_public_key(public_key, LNP_PUBLIC_KEY_LENGTH);
	util_join_byte  (packet, &offset, LNP_PUBLIC_KEY_RESPONSE);
	util_join_byte  (packet, &offset, ttl);
	util_join_bytes (packet, &offset, (u_char *)my_id, NET_ID_LENGTH);
	util_join_bytes (packet, &offset, (u_char *)id, NET_ID_LENGTH);
	util_join_byte  (packet, &offset, flags);
	util_join_mpint	(packet, &offset, public_key);
	util_join_bytes	(packet, &offset, lnp_key_store[store_entry_index].k_out,
			LNP_K_LENGTH);
	liblog_debug(LAYER_NET, "packet constructed.");
	
	/* Sending packet. */
	if (lnp_link_write(packet, offset) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error sending packet.");
		return LNP_ERROR;
	}
	liblog_debug(LAYER_NET, "packet sent.");

	return LNP_OK;
}
/******************************************************************************/
int send_key_exchange(net_id_t id, int store_entry_index) {
	int offset;
	u_char ttl = 0;
	u_char flags = 0;
	u_char packet[LNP_KEY_EXCHANGE_MAX_LENGTH];
	char cipher_string[LNP_FUNCTION_LIST_MAX_LENGTH];
	char hash_string[LNP_FUNCTION_LIST_MAX_LENGTH];
	char mac_string[LNP_FUNCTION_LIST_MAX_LENGTH];
	
	lnp_get_cipher_string(cipher_string, LNP_FUNCTION_LIST_MAX_LENGTH);
	lnp_get_hash_string(hash_string, LNP_FUNCTION_LIST_MAX_LENGTH);
	lnp_get_mac_string(mac_string, LNP_FUNCTION_LIST_MAX_LENGTH);
	
	/* Constructing key exchange packet. */
	offset = 0;
	util_join_byte  (packet, &offset, LNP_KEY_EXCHANGE);
	util_join_byte  (packet, &offset, ttl);
	util_join_bytes (packet, &offset, (u_char *)my_id, NET_ID_LENGTH);
	util_join_bytes (packet, &offset, (u_char *)id, NET_ID_LENGTH);
	util_join_byte  (packet, &offset, flags);
	util_join_string(packet, &offset, cipher_string);
	util_join_string(packet, &offset, hash_string);
	util_join_string(packet, &offset, mac_string);
	util_join_bytes	(packet, &offset,
			lnp_key_store[store_entry_index].k_in, LNP_K_LENGTH);
	util_join_bytes	(packet, &offset,
			lnp_key_store[store_entry_index].k_out, LNP_K_LENGTH);
	liblog_debug(LAYER_NET, "packet constructed.");
	
	/* Sending packet. */
	if (lnp_link_write(packet, offset) == LNP_ERROR) {
		liblog_debug(LAYER_NET, "error sending packet.");
		return LNP_ERROR;
	}
	
	liblog_debug(LAYER_NET, "packet sent.");

	return LNP_OK;
}
/******************************************************************************/
int send_key_exchange_ok(net_id_t id, int store_entry_index) {
	int offset;
	u_char ttl = 0;
	u_char flags = 0;
	u_char packet[LNP_KEY_EXCHANGE_OK_MAX_LENGTH];
	
	/* Constructing key exchange acknowledgment packet. */
	offset = 0;
	util_join_byte	(packet, &offset, LNP_KEY_EXCHANGE_OK);
	util_join_byte  (packet, &offset, ttl);
	util_join_bytes (packet, &offset, (u_char *)my_id, NET_ID_LENGTH);
	util_join_bytes (packet, &offset, (u_char *)id, NET_ID_LENGTH);
	util_join_byte  (packet, &offset, flags);
	util_join_string(packet, &offset,
			lnp_key_store[store_entry_index].cipher -> name);
	util_join_string(packet, &offset,
			lnp_key_store[store_entry_index].hash -> name);
	util_join_string(packet, &offset,
			lnp_key_store[store_entry_index].mac -> name);
	util_join_bytes	(packet, &offset,
			lnp_key_store[store_entry_index].k_in, LNP_K_LENGTH);
	
	/* Sending packet. */
	if (lnp_link_write(packet, offset) == LNP_ERROR) {
		liblog_debug(LAYER_NET, "error sending packet.");
		return LNP_ERROR;
	}
	
	liblog_debug(LAYER_NET, "packet sent.");
	
	return LNP_OK;	
}
/******************************************************************************/
int parse_public_key_request(lnp_public_key_request_p *packet,
		u_char *packet_data, int packet_size) {
	
	UTIL_READ_START(packet_data, packet_size, LNP_OK, LNP_ERROR)
	UTIL_READ_BYTE(packet->major_version)
	UTIL_READ_BYTE(packet->minor_version)
	UTIL_READ_BYTE(packet->transmission_mode)
	UTIL_READ_MPINT(packet->public_key)
	UTIL_READ_END
}	
/******************************************************************************/
inline int parse_public_key_response(lnp_public_key_response_p *packet,
		u_char *packet_data, int packet_length) {
	
	UTIL_READ_START(packet_data, packet_length, LNP_OK, LNP_ERROR)
	UTIL_READ_MPINT(packet->public_key)
	UTIL_READ_BYTES(packet->encrypted_k, LNP_K_LENGTH)
	UTIL_READ_END
}
/******************************************************************************/
int parse_key_exchange(lnp_key_exchange_p *packet, u_char *packet_data,
		int packet_length) {

	UTIL_READ_START(packet_data, packet_length, LNP_OK, LNP_ERROR)
	UTIL_READ_STRING(packet->ciphers)
	UTIL_READ_STRING(packet->hashes)
	UTIL_READ_STRING(packet->macs)
	UTIL_READ_BYTES(packet->encrypted_k_1, LNP_K_LENGTH)
	UTIL_READ_BYTES(packet->encrypted_k_2, LNP_K_LENGTH)
	UTIL_READ_END
}
/******************************************************************************/
int parse_key_exchange_ok(lnp_key_exchange_ok_p *packet, u_char *packet_data,
		int packet_length) {
	UTIL_READ_START(packet_data, packet_length, LNP_OK, LNP_ERROR)
	UTIL_READ_STRING(packet->cipher)
	UTIL_READ_STRING(packet->hash)
	UTIL_READ_STRING(packet->mac)
	UTIL_READ_BYTES(packet->encrypted_k, LNP_K_LENGTH)
	UTIL_READ_END
}
/******************************************************************************/
