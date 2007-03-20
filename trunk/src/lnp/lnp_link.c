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
 * @file lnp_link.c Implementations of routines used to manipulate the LNP
 * 		module socket.
 * @ingroup lnp
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libfreedom/liblog.h>
#include <libfreedom/layers.h>

#include <util/util_crypto.h>
#include <util/util_data.h>

#include "lnp.h"
#include "lnp_data.h"
#include "lnp_packets.h"
#include "lnp_handshake.h"
#include "lnp_routing_policy.h"
#include "lnp_collision_table.h"
 
/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/**
 * 
 */
#define MIN_PACKET_LENGTH	42

/**
 * TODO botar constante no layers.h?
 */
#define MAX_SESSIONS 256

/**
 * 
 */ 
static u_char active_sessions[MAX_SESSIONS];

/**
 * 
 */
static util_hash_function_t *hash;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

int handle_packet(u_char *packet_data, int packet_length, int session_from);
int parse_packet(lnp_packet_p *packet, u_char *packet_data, int packet_length);
int receive_packet(lnp_packet_p *packet, int packet_length);
int send_broadcast(int last_session, u_char *packet, int length);
int send_back(int last_session, u_char *packet, int length);
int send_back_with_error(int last_session, u_char *packet, int length);
int send_unicast(int link_session, u_char *packet, int length);
int send_packet(int link_session, u_char *packet, int length);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

void lnp_listen_link() {
	int session_from;
	static u_char packet_data[LIBFREEDOM_FTU];
	int packet_length;
	
	hash = util_get_hash("sha1"); 
	
	while (1) {
		liblog_debug(LAYER_NET, "listening in link layer.");
		packet_length = link_interface->link_read(&session_from, packet_data,
				LIBFREEDOM_FTU);
		liblog_debug(LAYER_NET, "packet with %d bytes received.",
				packet_length);
		if (packet_length < 0) {
			liblog_error(LAYER_NET, "error receiving data.");
			return;
		}
		if (packet_length < MIN_PACKET_LENGTH) {
			liblog_error(LAYER_NET, "packet is too small to be valid.");
			continue;
		}
		handle_packet(packet_data, packet_length, session_from);		
	}
	return;
}
/******************************************************************************/
int lnp_link_write(u_char *packet_data, int packet_length) {
	return handle_packet(packet_data, packet_length, -1);
}
/******************************************************************************/
void lnp_link_close_handler(int session) {
	/* TODO: Confirmar a não-necessidade de mutex em 'active_sessions'*/
	if (active_sessions[session]) {
		liblog_debug(LAYER_NET, "session %d closed.", session);
	}
	active_sessions[session] = 0;
}
/******************************************************************************/
void lnp_link_connect_handler(int session) {
	if (!active_sessions[session]) {
		liblog_debug(LAYER_NET, "session %d opened.", session);
	}
	active_sessions[session] = 1;
}
/******************************************************************************/
u_char lnp_is_session_active(int session) {
	return active_sessions[session];
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int handle_packet(u_char *packet_data, int packet_length, int session_from) {
	u_char packet_hash[COLLISION_HASH_LENGTH];
	lnp_packet_p packet;
	int parse_result;
	int session_to;
	static int hash_offset = 3 * sizeof(u_char) + 2 * NET_ID_LENGTH;
	
	liblog_debug(LAYER_NET, "packet received from session %d.", session_from);
	
	parse_result = parse_packet(&packet, packet_data, packet_length);
	if (parse_result == LNP_ERROR) {
		liblog_error(LAYER_NET, "packet couldn't be parsed.");
		return LNP_ERROR;
	}
	packet.content = &packet_data[hash_offset];
	
	hash->function(packet_hash, packet.content, 
			packet_length - hash_offset);
	
	session_to = lnp_routing_handle(packet.source, packet.destination,
			packet_hash, packet.flags, session_from);
	liblog_debug(LAYER_NET, "session_to %d.", session_to);
			
	if (session_to >= 0) {
		return send_unicast(session_to, packet_data, packet_length);
	} else {
		switch (session_to) {
			case LNP_ROUTE_RECEIVE:
				return receive_packet(&packet, packet_length - hash_offset);
			case LNP_ROUTE_BACK:
				return send_back(session_from, packet_data, packet_length);
			case LNP_ROUTE_BACK_WITH_ERROR:
				/* TODO : checar*/
				send_broadcast(session_from, packet_data, packet_length);
				return send_back_with_error(session_from, packet_data, 
						packet_length);
			case LNP_ROUTE_BROADCAST:
				return send_broadcast(session_from, packet_data, packet_length);
			case LNP_ROUTE_DROP:
				/* do nothing */
				liblog_debug(LAYER_NET, "packet droped.");
				return LNP_OK;
			default:
				return LNP_ERROR;
		}
	}
}
/******************************************************************************/
int parse_packet(lnp_packet_p *packet, u_char *packet_data, int packet_length) {
	UTIL_READ_START(packet_data, packet_length, LNP_OK, LNP_ERROR)
	UTIL_READ_BYTE (packet->type)
	UTIL_READ_BYTE (packet->ttl)
	UTIL_READ_BYTES(packet->source, NET_ID_LENGTH)
	UTIL_READ_BYTES(packet->destination, NET_ID_LENGTH)
	UTIL_READ_BYTE (packet->flags)
	UTIL_READ_END
}
/******************************************************************************/
int receive_packet(lnp_packet_p *packet, int content_length) {
	liblog_debug(LAYER_NET, "packet is mine. type=%d.", packet->type);
	switch (packet->type) {
		case LNP_PUBLIC_KEY_REQUEST:
			lnp_handle_public_key_request(packet, content_length);
			break;
		case LNP_PUBLIC_KEY_RESPONSE:
			lnp_handle_public_key_response(packet, content_length);
			break;
		case LNP_KEY_EXCHANGE:
			lnp_handle_key_exchange(packet, content_length);
			break;
		case LNP_KEY_EXCHANGE_OK:
			lnp_handle_key_exchange_ok(packet, content_length);
			break;
		case LNP_DATA:
			lnp_handle_data(packet, content_length);
			break;
		default:
			return LNP_ERROR;
	}
	return LNP_OK;
}		
/******************************************************************************/		
int send_broadcast(int last_session, u_char *packet, int length) {
	int i;
	int return_value = LNP_ERROR;
	liblog_debug(LAYER_NET, "broadcasting.");
	for (i = 0; i < MAX_SESSIONS; i++) {
		if ((active_sessions[i]) && (i != last_session)) {
			if (send_packet(i, packet, length) == LNP_OK) {
				return_value = LNP_OK;
			}
		}
	}
	return return_value;
}
/******************************************************************************/		
int send_back(int last_session, u_char *packet, int length) {
	liblog_debug(LAYER_NET, "sending back.");
	return send_packet(last_session, packet, length);
}
/******************************************************************************/		
int send_back_with_error(int last_session, u_char *packet, int length) {
	liblog_debug(LAYER_NET, "sending back with error.");
	// TODO: setar bit de erro
	return send_packet(last_session, packet, length);
}
/******************************************************************************/		
int send_unicast(int link_session, u_char *packet, int length) {
	liblog_debug(LAYER_NET, "sending unicast.");
	// TODO: tirar ttl
	return send_packet(link_session, packet, length);
}
/******************************************************************************/		
int send_packet(int link_session, u_char *packet, int length) {
	int return_value;
	liblog_debug(LAYER_NET, "sending packet to %d: %d bytes", 
			link_session, length);
	return_value = link_interface->link_write(link_session, packet, length);
	
	if (return_value == LINK_ERROR) {
		liblog_debug(LAYER_NET, "packet wasn't sent.");
	}
	liblog_debug(LAYER_NET, "packet was sent.");
	
	return (return_value == LINK_ERROR ? LNP_ERROR : LNP_OK);
}
/******************************************************************************/
