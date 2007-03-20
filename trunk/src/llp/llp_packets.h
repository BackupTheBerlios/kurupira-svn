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
 * @file llp_packets.h Headers of routines used to manipulate packets.
 * @ingroup llp
 */

#ifndef _LLP_PACKETS_H_
#define _LLP_PACKETS_H_

#include <netinet/in.h>

#include <libfreedom/types.h>

#include "llp_config.h"

/**
 * Defines the size in bytes (including the \\0) of a function list string.
 */
#define LLP_FUNCTION_LIST_MAX_LENGTH	(256 + STRING_SIZE_LENGTH)
/**
 * Defines the size in bytes (including the \\0) of a function name identifier.
 */
#define LLP_FUNCTION_NAME_MAX_LENGTH	(256 + STRING_SIZE_LENGTH)
/**
 * Defines the size in bytes of parameters h_in and h_out, used in key
 * agreement.
 */
#define LLP_H_LENGTH	16
/**
 * Defines the size in bytes of a Diffie-Hellman exponent (including the 5 mpint
 * representation bytes).
 */
#define LLP_X_LENGTH	(32 + MPINT_SIZE_LENGTH + MPINT_SIGNAL_LENGTH)
/**
 * Defines the size in bytes of a (g^x mod p) computation result.
 */
#define LLP_Y_LENGTH	(256 + MPINT_SIZE_LENGTH + MPINT_SIGNAL_LENGTH)
/**
 * Defines the size of a key established by Diffie & Hellman key agreement.
 */
#define LLP_Z_LENGTH	(256 + MPINT_SIZE_LENGTH + MPINT_SIGNAL_LENGTH)
/**
 * Defines the minimum padding to be added to packets.
 */
#define LLP_MIN_PADDING_LENGTH	4

/**
 * Enumeration that defines the types of packets used by LLP.
 */
enum llp_packet_ids {
	LLP_CONNECTION_REQUEST = 1,	/**< establishes a new connection. */
	LLP_CONNECTION_OK,			/**< acknowledges LLP_CONNECTION_REQUEST. */
	LLP_KEY_EXCHANGE,			/**< finalizes the three-way handshake. */
	LLP_DATA,					/**< packet used in established connections */
	LLP_CLOSE_REQUEST,			/**< requests the closing of a session. */
	LLP_CLOSE_OK,				/**< acknowledges LLP_CLOSE_REQUEST. */
	LLP_NODE_HUNT,				/**< requests a list of hosts to connect. */
	LLP_HUNT_RESULT,			/**< transports a list of hosts to connect. */
	LLP_KEEP_ALIVE,				/**< detects if connected peers are alive. */
	LLP_DATAGRAM = 15,			/**< generic data sent by upper layers. */
};

/**
 * Enumeration that defines the types of addresses supported/
 */
enum llp_address_types {
	LLP_ADDRESS_INET = 1	/**< IPv4 addresses. */
};

/**
 * Defines the max length in bytes of a LLP_CONNECTION_REQUEST packet.
 */ 
#define LLP_CONNECTION_REQUEST_MAX_LENGTH							\
		(3 * sizeof(u_char) + sizeof(u_short) + 3 *					\
		LLP_FUNCTION_LIST_MAX_LENGTH + LLP_H_LENGTH)

/**
 * Defines the max length in bytes of a LLP_CONNECTION_OK packet.
 */
#define LLP_CONNECTION_OK_MAX_LENGTH								\
		(2 * sizeof(u_char) + 3 * LLP_FUNCTION_LIST_MAX_LENGTH +	\
		LLP_H_LENGTH + LLP_Y_LENGTH)
		
/**
 * Defines the max length in bytes of a LLP_KEY_EXCHANGE packet.
 */
#define LLP_KEY_EXCHANGE_MAX_LENGTH (sizeof(u_char) + LLP_Y_LENGTH)

/**
 * Defines the type os addresses returned in node hunt responses.
 */
#define LLP_ADDRESS_INET_LENGTH			(sizeof(u_char) + 6)

/**
 * Defines the max length of a LLP_HUNT_RESULT packet;
 */
#define LLP_HUNT_RESULT_MAX_LENGTH		(255 * LLP_ADDRESS_INET_LENGTH +	\
		sizeof(u_char))

/**
 * Packet LLP_CONNECTION_REQUEST, used to establish new connections.
 */
typedef struct {
	/** Major version of LLP protocol. */
	u_char major_version;
	/** Minor version of LLP protocol. */
	u_char minor_version;
	/** Session number in host sending this packet. */
	u_char session; 		
	/** List of ciphers supported. */
	char ciphers[LLP_FUNCTION_LIST_MAX_LENGTH];	
	/** List of hash functions supported. */
	char hashes[LLP_FUNCTION_LIST_MAX_LENGTH];
	/** List of MAC algorithms supported. */
	char macs[LLP_FUNCTION_LIST_MAX_LENGTH];
	/** Equals h_out to this host and h_in to remote.*/
	u_char h[LLP_H_LENGTH];
} llp_connection_request_p;

/**
 * Packet LLP_CONNECTION_OK, used to acknowledge a connection request.
 */
typedef struct {
	/** Session number in initiator node. */
	u_char session_dst;
	/** Session number in receiver node (this host). */
	u_char session_src;
	/** Chosen cipher algorithm identifier. */
	char cipher[LLP_FUNCTION_NAME_MAX_LENGTH];
	/** Chosen hash function identifier. */
	char hash[LLP_FUNCTION_NAME_MAX_LENGTH];
	/** Chosen MAC algorithm identifier. */
	char mac[LLP_FUNCTION_NAME_MAX_LENGTH];
	/** Equals h_out to this host and h_in to remote. */
	u_char h[LLP_H_LENGTH];
	/** Equals y_out to this host and y_in to remote. */
	u_char y[LLP_Y_LENGTH];
} llp_connection_ok_packet_p;

/**
 * Packet LLP_KEY_EXCHANGE, used to finalize the handshake and transmission
 * of parameters needed by the peers involved generate their keys.
 */
typedef struct {
	u_char session;			/**< Session number in remote node (peer). */
	u_char y[LLP_Y_LENGTH];	/**< Equals y_out to this host and y_in to remote.*/
} llp_key_exchange_p;

/**
 * Packet LLP_CLOSE_REQUEST, used to request a session close.
 */
typedef struct {
	/** HASH(z), to prove that the host sending the packet is the connected
	 * peer. */
	u_char *verifier;
} llp_close_request_p;

/**
 * Packet LLP_CLOSE_OK, used to acknowledge a session close.
 */
typedef struct {
	/** HASH(z), to prove that the host sending the packet is the connected
	 * peer. */
	u_char *verifier;
} llp_close_ok_p;

/**
 * Data type used to store a node address in LLP_HUNT_RESULT packets.
 */
typedef struct {
	/** Specifies the size in bytes of a host address. */
	u_char address_type;
	/** The host address. */
	u_int address;
	/** The port used by the host to receive connections. */
	u_short port;
} llp_address_t;

/**
 * Packet LLP_HUNT_RESULT, used to send a list of nodes.
 */
typedef struct {
	/** Number of hosts returned. */
	u_char size;
	/** Lists of hosts obtained. */
	llp_address_t *list;
} llp_hunt_result_p;

/**
 * Packet LLP_DATAGRAM, used to send generic data.
 */
typedef struct {
	/** Data carried by this packet. */
	u_char *data;
} llp_datagram_p;

/**
 * Packet transported by a LLP_DATA packet.
 */
typedef union {
	/** This packet carries a LLP_CLOSE_REQUEST packet. */
	llp_close_request_p close_request;
	/** This packet carries a LLP_CLOSE_PK packet. */
	llp_close_ok_p close_ok;
	/** This packet carries a LLP_HUNT_RESULT packet. */
	llp_hunt_result_p hunt_result;
	/** This packet carries a LLP_DATAGRAM packet. */
	llp_datagram_p datagram;
} llp_data_content_p;

/**
 * Packet LLP_DATA, used to transmit data by a already established connection.
 */
typedef struct {
	/** Session number in remote peer (the one that will receive this packet).*/
	u_char session;
	/** Length of padding added for cipher block size alignment purposes. */
	u_short padding_length;
	/** The padding. */
	u_char *padding;
	/** Packet identifier. */
	u_char content_type;
	/** Data transported by this packet. */
	llp_data_content_p content;
	/** MAC generated from this packet. */
	u_char *mac;
} llp_data_p;

/**
 * Macro to simplify packet treatment.
 */
#define llp_close_request	content.close_request
/**
 * Macro to simplify packet treatment.
 */
#define llp_close_ok		content.close_ok
/**
 * Macro to simplify packet treatment.
 */
#define llp_hunt_result		content.hunt_result
/**
 * Macro to simplify packet treatment.
 */
#define llp_datagram		content.datagram

/**
 * Union that represents all types of LLP packets.
 */
typedef union {
	/** This packet carries a LLP_CONNECTION_REQUEST packet. */
	llp_connection_request_p connection_request;
	/** This packet carries a LLP_CONNECTION_OK packet. */
	llp_connection_ok_packet_p connection_ok;
	/** This packet carries a LLP_KEY_EXCHANGE packet. */
	llp_key_exchange_p key_exchange;
	/** This packet carries a LLP_DATA packet. */
	llp_data_p data;
} llp_packet_content_p;

/**
 * Structure that represents a LLP packet.
 */
typedef union {
	/** Packet identifier. */
	u_char type;
	/** Packet content. */
	llp_packet_content_p content;
} llp_packet_p;

/**
 * Macro to simplify packet treatment.
 */
#define llp_connection_request 	content.connection_request
/**
 * Macro to simplify packet treatment.
 */
#define llp_connection_ok 		content.connection_ok
/**
 * Macro to simplify packet treatment.
 */
#define llp_key_exchange		content.key_exchange
/**
 * Macro to simplify packet treatment.
 */
#define llp_data				content.data

/**
 * Sends a packet to a given host.
 * 
 * @param address host identifier.
 * @param packet packet data.
 * @param length packet length in bytes.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_send_direct_packet(struct sockaddr_in* address, u_char *packet,
		int length);

/**
 * Sends a packet by the given session.
 * 
 * @param session session identifier.
 * @param packet packet data.
 * @param length packet length in bytes.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_send_session_packet(int session, u_char *packet, int length);

#endif /* !_LLP_PACKETS_H_ */
