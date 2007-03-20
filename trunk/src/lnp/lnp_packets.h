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
 * @file lnp_packets.h Headers of routines used to manipulate packets.
 * @ingroup lnp
 */

#ifndef _LNP_PACKETS_H_
#define _LNP_PACKETS_H_

#include <netinet/in.h>

#include <libfreedom/layer_net.h>
#include <libfreedom/types.h>

/**
 * Defines the size in bytes (including the \\0) of a function list string.
 */
#define LNP_FUNCTION_LIST_MAX_LENGTH	(128 + STRING_SIZE_LENGTH)
/**
 * Defines the size in bytes (including the \\0) of a function name identifier.
 */
#define LNP_FUNCTION_NAME_MAX_LENGTH	(128 + STRING_SIZE_LENGTH)
/**
 * Defines the size in bytes of an RSA represented as a byte array.
 */
#define LNP_PUBLIC_KEY_LENGTH		\
		(140 + MPINT_SIZE_LENGTH + MPINT_SIGNAL_LENGTH)

/**
 * Defines the size in bytes of a shared secret k.
 */
#define LNP_K_LENGTH			32

/**
 * Defines the minimum padding to be added to packets.
 */
#define LNP_MIN_PADDING_LENGTH	4

/**
 * Enumeration that defines the types of packets used by LLP.
 */
enum llp_packet_ids {
	LNP_PUBLIC_KEY_REQUEST,	/**< */
	LNP_PUBLIC_KEY_RESPONSE,/**< */
	LNP_KEY_EXCHANGE,		/**< */
	LNP_KEY_EXCHANGE_OK,	/**< */
	LNP_DATA				/**< */
};

/**
 * Defines the max length in bytes of a LNP_PUBLIC_KEY_REQUEST packet.
 */
#define LNP_PUBLIC_KEY_REQUEST_MAX_LENGTH			\
		(4 * sizeof(u_char) + 2 * sizeof(net_id_t) +\
		LNP_PUBLIC_KEY_LENGTH)
		
/**
 * Defines the max length in bytes of a LLP_PUBLIC_KEY_RESPONSE packet.
 */
#define LNP_PUBLIC_KEY_RESPONSE_MAX_LENGTH			\
		(sizeof(u_char) + 2 * sizeof(net_id_t) +	\
		LNP_PUBLIC_KEY_LENGTH + LNP_K_LENGTH)
		
/**
 * Defines the max length in bytes of a LNP_KEY_EXCHANGE packet.
 */
#define LNP_KEY_EXCHANGE_MAX_LENGTH					\
		(sizeof(u_char) + 2 * sizeof(net_id_t) +	\
		LNP_FUNCTION_LIST_MAX_LENGTH + 2 * LNP_K_LENGTH)

/**
 * Defines the max length in bytes of a LNP_KEY_EXCHANGE_OK packet.
 */
#define LNP_KEY_EXCHANGE_OK_MAX_LENGTH				\
		(sizeof(u_char) + 2 * sizeof(net_id_t) +	\
		LNP_FUNCTION_NAME_MAX_LENGTH + LNP_K_LENGTH)

/** */
#define LNP_BROADCAST	1
/** */
#define LNP_UNICAST		0

/**
 * Packet LLP_PUBLIC_KEY_REQUEST, used to establish new connections.
 */
typedef struct {
	/** Major version of LNP protocol. */
	u_char major_version;
	/** Minor version of LNP protocol. */
	u_char minor_version;
	/** Transmission mode (unicast or broadcast). */
	u_char transmission_mode;
	/** Public key dump in DER format. */
	u_char public_key[LNP_PUBLIC_KEY_LENGTH];
} lnp_public_key_request_p;

/**
 * Packet LNP_PUBLIC_KEY_RESPONSE, used to establish new connections.
 */
typedef struct {
	/** Public key dump in DER format. */
	u_char public_key[LNP_PUBLIC_KEY_LENGTH];
	/** Shared secret k_1. */
	u_char encrypted_k[LNP_K_LENGTH];
} lnp_public_key_response_p;

/**
 * Packet LNP_KEY_EXCHANGE, used to exchange shared keys.
 */
typedef struct {
	/** List of ciphers supported. */
	char ciphers[LNP_FUNCTION_LIST_MAX_LENGTH];	
	/** List of hash functions supported. */
	char hashes[LNP_FUNCTION_LIST_MAX_LENGTH];
	/** List of MAC algorithms supported. */
	char macs[LNP_FUNCTION_LIST_MAX_LENGTH];
	/** Shared secret k_1. */
	u_char encrypted_k_1[LNP_K_LENGTH];
	/** Shared secret k_2. */
	u_char encrypted_k_2[LNP_K_LENGTH];
} lnp_key_exchange_p;

/**
 * Packet LLP_KEY_EXCHANGE_OK, used to acknowledge a shared key exchange.
 */
typedef struct {
	/** List of ciphers supported. */
	char cipher[LNP_FUNCTION_NAME_MAX_LENGTH];	
	/** List of hash functions supported. */
	char hash[LNP_FUNCTION_NAME_MAX_LENGTH];
	/** List of MAC algorithms supported. */
	char mac[LNP_FUNCTION_NAME_MAX_LENGTH];
	/** Shared secret k_2. */
	u_char encrypted_k[LNP_K_LENGTH];
} lnp_key_exchange_ok_p;

/**
 * Packet LNP_DATA, used to transmit data to an already known ID.
 */
typedef struct {
	/** The padding. */
	u_char *padding;
	/** Protocol identifier. */
	u_char protocol;
	/** Timestamp. */
	u_short timestamp;
	/** Data transported by this packet. */
	u_char *data;
	/** Length of padding added for cipher block size alignment purposes. */
	u_short padding_length;
	/** MAC generated from this packet. */
	u_char *mac;
} lnp_data_p;

/**
 * Union that represents all types of LNP packets.
 */
typedef union {
	/** */
	lnp_public_key_request_p public_key_request;
	/** */
	lnp_public_key_response_p public_key_response;
	/** */
	lnp_key_exchange_p key_exchange;
	/** */
	lnp_key_exchange_ok_p key_exchange_ok;
	/** */
	lnp_data_p data;
} lnp_packet_content_p;

/**
 * Structure that represents a LNP packet.
 */
typedef struct {
	/** Packet identifier. */
	u_char type;
	/** Packet TTL. */
	u_char ttl;
	/** Source ID address. */
	net_id_t source;
	/** Destination ID address. */
	net_id_t destination;
	/** Packet duplication and routing error flags. */
	u_char flags;
	/** Packet content. */
	u_char *content;
} lnp_packet_p;

/**
 * Macro to simplify packet treatment.
 */
#define lnp_public_key_request 	content.public_key_request
/**
 * Macro to simplify packet treatment.
 */
#define lnp_public_key_response	content.public_key_response
/**
 * Macro to simplify packet treatment.
 */
#define lnp_key_exchange		content.key_exchange
/**
 * Macro to simplify packet treatment.
 */
#define lnp_key_exchange_ok		content.key_exchange_ok
/**
 * Macro to simplify packet treatment.
 */
#define lnp_data				content.data

/**
 * Sends a packet by the given session.
 * 
 * @param link_session session identifier in link layer.
 * @param packet packet data.
 * @param length packet length in bytes.
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_send_packet(int link_session, u_char *packet, int length);

#endif /* !_LNP_PACKETS_H_ */
