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
 * @file lnp_data.c Implementations of functions used to manipulate LNP_DATA
 * 		packets.
 * @ingroup lnp
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

#include <libfreedom/liblog.h>
#include <util/util_crypto.h>
#include <util/util_data.h>
#include <util/util.h>

#include "lnp.h"
#include "lnp_id.h"
#include "lnp_data.h"
#include "lnp_link.h"
#include "lnp_clocks.h"
#include "lnp_packets.h"
#include "lnp_queue.h"
#include "lnp_store.h"
#include "lnp_routing_table.h"

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

/*
 * Sends a LNP_DATA packet, given its contents.
 */
static int send_data(net_id_t id_to, u_char *data, int length, u_char protocol);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int lnp_handle_data(lnp_packet_p *packet, int content_length) {
	int return_value;
	int mac_length;
	u_short padding_length;
	int offset;
	u_char *plain_content = NULL;
	u_char *mac = NULL;
	u_char *real_mac = NULL;
	int routing_entry_index;
	int store_entry_index;
	u_char protocol;
	u_short timestamp;
	
	routing_entry_index = lnp_routing_entry_lock(packet->source);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		liblog_error(LAYER_NET, "connection not established.");
		return LNP_ERROR; /* TODO colocar constantes adequada para este erro */
	}
		
	if (routing_table[routing_entry_index].store_index == NULL_SLOT) {
		/* TODO verificar */
		liblog_error(LAYER_NET, "connection not established.");
		return_value = LNP_ERROR;
		goto return_label;
	} else {
		store_entry_index = routing_table[routing_entry_index].store_index;
	}

	/* Calculating lengths before using them */
	if (lnp_key_store[store_entry_index].mac == NULL) {
		/* TODO retirar isso */
		mac_length = 0;
	} else {
		mac_length = lnp_key_store[store_entry_index].mac->length;
	}
	content_length = content_length - mac_length;
	mac = &packet->content[content_length];
	
	/* Allocating memory for packet. */
	plain_content = (u_char *)malloc(content_length);
	real_mac = (u_char *)malloc(mac_length);
	if (real_mac == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.", strerror(errno));
		return_value = LNP_ERROR;
		goto return_label;
	}
	
	/* Decrypting content. */
	lnp_key_store[store_entry_index].cipher->function(plain_content,
			packet->content, 
			lnp_key_store[store_entry_index].cipher_in_key,
			lnp_key_store[store_entry_index].cipher_in_iv, 
			content_length,
			UTIL_WAY_DECRYPTION);
	
	
	liblog_debug(LAYER_NET, "packet decrypted.");

	/* Read the data after decrypted. */
	offset = content_length - sizeof(u_short);
	util_read_uint16(&padding_length, &offset, plain_content);
	
	offset = padding_length;
	util_read_byte  (&protocol, &offset, plain_content);
	util_read_uint16(&timestamp, &offset, plain_content);

	/* Generation MAC of the plain content. */
	if (lnp_key_store[store_entry_index].mac != NULL) {
		/* TODO: retirar esse if == NULL*/
		lnp_key_store[store_entry_index].mac->function(real_mac, plain_content,
				lnp_key_store[store_entry_index].mac_in_key, content_length);
	}

	if (memcmp(mac, real_mac, mac_length) != 0) {
		/* Drop packet. */
		liblog_error(LAYER_NET, "MAC mismatch. packet dropped.");
		return_value = LNP_ERROR;
		goto return_label;
	}
	
	liblog_debug(LAYER_NET, "MAC verified.");
	
	return_value = lnp_enqueue_datagram(packet->source,
			&plain_content[padding_length + (sizeof(u_char) + sizeof(u_short))], 
			content_length - padding_length 
					- (sizeof(u_char) + sizeof(u_short)) /* proto + tmstmp */
					- sizeof(u_short), /* padding length field */
			protocol);

return_label:
			
	free(plain_content);
	free(real_mac);

	/* unlock routing entry */
	lnp_routing_entry_unlock(routing_entry_index);

	return return_value;
}
/******************************************************************************/
int lnp_read(net_id_t from, u_char *data, int max, u_char protocol) {
	int return_value = lnp_dequeue_datagram(from, data, max, protocol);
	return (return_value == LNP_ERROR ? NET_ERROR : return_value);
}
/******************************************************************************/
int lnp_flush(u_char protocol) {
	net_id_t from;
	int return_value = 0;
	
	while (lnp_try_dequeue_datagram(from, NULL, -1, protocol) != LNP_ERROR) {
		return_value++;	
	}
	return return_value;
}
/******************************************************************************/
int lnp_write(net_id_t id_to, u_char *data, int length, u_char protocol) {
	int return_value;

	/* TODO TIRAR ISSO AKI!! */
	int routing_entry_index = lnp_add_id(id_to);
	int store_key_index = routing_table[routing_entry_index].store_index;
	if (store_key_index == NULL_SLOT) {
		store_key_index = lnp_key_store_new();
		routing_table[routing_entry_index].store_index = store_key_index;
		lnp_key_store[store_key_index].cipher = util_get_cipher("none");
	}
	liblog_debug(LAYER_NET, "store_key_index %d\n", store_key_index);
	
	return_value = send_data(id_to, data, length, protocol);
	
	return (return_value == LNP_OK ? NET_OK : NET_ERROR);
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int send_data(net_id_t id_to, u_char *data, int length, u_char protocol) {
	int return_value;
	int offset;
	u_short padding_length;
	int packet_length;
	int content_length;
	int mac_length;
	u_char *mac = NULL;
	u_char *padding = NULL;
	u_char *packet = NULL;
	u_char *content = NULL;
	u_char *plain_content = NULL;
	u_char ttl = 0;
	u_char flags = 0;
	int routing_entry_index;
	int store_entry_index;
	
	routing_entry_index = lnp_routing_entry_lock(id_to);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		liblog_error(LAYER_NET, "connection not established.");
		return LNP_ERROR; /* TODO colocar constantes adequada para este erro */
	}
		
	if (routing_table[routing_entry_index].store_index == NULL_SLOT) {
		liblog_error(LAYER_NET, "connection not established.");
		return_value = LNP_ERROR;
		goto return_label;
	} else {
		store_entry_index = routing_table[routing_entry_index].store_index;
	}

	/* Determining the MAC length. */
	if (lnp_key_store[store_entry_index].mac == NULL) {
		/* TODO retirar isso */
		mac_length = 0;
	} else {
		mac_length = lnp_key_store[store_entry_index].mac->length;
	}

	/* Computing padding length. */
	padding_length = LIBFREEDOM_FTU;
	padding_length = padding_length 
			- (3*sizeof(u_char) + 2*NET_ID_LENGTH) /* header */
			- mac_length; /* mac */
	/* alignment */			
	padding_length = padding_length - (padding_length % 
			lnp_key_store[store_entry_index].cipher->block_size);
	padding_length = padding_length 
			- (sizeof(u_char) + 2*sizeof(u_short)) /* proto + timestamp + pad */
			- length; /* payload */
	if (padding_length < LNP_MIN_PADDING_LENGTH) {
		liblog_error(LAYER_NET, "packet too large.");
		return_value = LNP_ERROR;
		goto return_label;
		/*padding_length += lnp_key_store[store_entry_index].cipher->block_size;*/
	}
	
	/* Determining content length. */
	content_length = 
			(sizeof(u_char) + 2*sizeof(u_short)) /* proto + timestamp + pad */
			+ padding_length 
			+ length;
	
	/* Determining the packet_size. */
	packet_length = 3*sizeof(u_char) + 2*NET_ID_LENGTH 
			+ content_length
			+ mac_length;

	liblog_debug(LAYER_NET, "payload has %d bytes, MAC = %d, content = %d, FTU = %d\n",
			length, mac_length, content_length, LIBFREEDOM_FTU);
	liblog_debug(LAYER_NET, "padding will be %d bytes long and packet will be "
			"%d bytes long.", padding_length, packet_length);

	/* Allocating buffers. */
	packet = (u_char*)malloc(packet_length);
	padding = (u_char*)malloc(padding_length);
	plain_content = (u_char*)malloc(content_length);
	mac = (u_char*)malloc(mac_length);

	if (packet == NULL || plain_content == NULL || mac == NULL ||
			padding == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.", strerror(errno));
		return_value = LNP_ERROR;
		goto return_label;
	}
	
	liblog_debug(LAYER_NET, "memory for packet construction allocated.");
	
	/* Generating padding. */
	if (util_rand_bytes(padding, padding_length) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error generating padding.");
		return_value = LNP_ERROR;
		goto return_label;
	}
	
	/* Constructing content. */
	offset = 0;
	util_rand_bytes (padding, padding_length);
	util_join_bytes (plain_content, &offset, padding, padding_length);
	util_join_byte  (plain_content, &offset, protocol);
	util_join_uint16(plain_content, &offset, lnp_get_local_clock());
	util_join_bytes (plain_content, &offset, data, length);
	util_join_uint16(plain_content, &offset, padding_length);
	
	/* Generating MAC of the plaintext content. */
	if (lnp_key_store[store_entry_index].mac != NULL) {
		/* TODO: tirar todos os mac==NULL) */
		lnp_key_store[store_entry_index].mac->function(mac, plain_content,
				lnp_key_store[store_entry_index].mac_out_key, content_length);
	}
	
	/* Constructing LNP_DATA packet. */
	offset = 0;
	util_join_byte  (packet, &offset, LNP_DATA);
	util_join_byte	(packet, &offset, ttl);
	util_join_bytes	(packet, &offset, my_id, NET_ID_LENGTH);
	util_join_bytes	(packet, &offset, id_to, NET_ID_LENGTH);
	util_join_byte	(packet, &offset, flags);

	/* Placing encrypted content in packet. */
	content = &packet[offset]; /* address to content be placed */
	offset += content_length;  /* skipping the content field */

	/* Writing MAC on packet. */
	util_join_bytes (packet, &offset, mac, mac_length);
	
	/* Encrypting content */
	lnp_key_store[store_entry_index].cipher->function(content, plain_content, 
			lnp_key_store[store_entry_index].cipher_out_key,
			lnp_key_store[store_entry_index].cipher_out_iv, content_length,
			UTIL_WAY_ENCRYPTION);
			
	return_value = LNP_OK;
	
	/* Sending packet. */
	if (lnp_link_write(packet, offset) == LNP_ERROR) {
		liblog_debug(LAYER_NET, "error sending packet.");
		return_value = LNP_ERROR;
		goto return_label;
	}
	
	liblog_debug(LAYER_NET, "packet sent.");

return_label:
	
	free(packet);
	free(plain_content);
	free(mac);
	free(padding);
	
	/* unlock routing entry */
	lnp_routing_entry_unlock(routing_entry_index);
	
	return return_value;
}
/******************************************************************************/
