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
 * @file llp_socket.c Implementations of routines used to manipulate the LLP
 * 		module socket.
 * @ingroup llp
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libfreedom/liblog.h>
#include <libfreedom/layers.h>

#include "llp_socket.h"
#include "llp_packets.h"
#include "llp_handshake.h"
#include "llp_data.h"
#include "llp.h"
 
/*============================================================================*/
/* Public data definitions.                                                   */
/*============================================================================*/

int llp_socket = LLP_CLOSED_SOCKET;

/*
 * Max length of a UDP packet in bytes.
 */
#define UDP_PACKET_MAX_LENGTH	65536

/*
 * Min length of a LLP packet in bytes.
 */
#define MIN_PACKET_LENGTH		5

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_create_socket(int port) {
	struct sockaddr_in server;
	
	/* Creating the socket. */
	llp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if(llp_socket == LLP_CLOSED_SOCKET) {
		liblog_error(LAYER_LINK, "error creating socket: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	liblog_info(LAYER_LINK, "socket created");
	
	/* Settting up the server. */
	server.sin_family = AF_INET;
	server.sin_port = htons(port); 
	server.sin_addr.s_addr = INADDR_ANY;

	/* Binding the socket. */
	if (bind(llp_socket, (struct sockaddr *)&server, sizeof(server))) {
		liblog_error(LAYER_LINK, "error binding socket: %s.", strerror(errno));
		return LLP_ERROR;
	}

	liblog_info(LAYER_LINK, "socket binded.");
	
	return LLP_OK;
}
/******************************************************************************/
void llp_close_socket() {
	if (llp_socket != LLP_CLOSED_SOCKET) {
		close(llp_socket);
	}
}
/******************************************************************************/
void llp_listen_socket() {
	struct sockaddr_in peer;
	u_int peer_address_size;
	static u_char packet[UDP_PACKET_MAX_LENGTH];
	int packet_length;
	
	peer_address_size = sizeof(struct sockaddr_in);
	
	while (1) {
		liblog_debug(LAYER_LINK, "listening in socket.");
		packet_length = recvfrom(llp_socket, packet, UDP_PACKET_MAX_LENGTH, 0, 
				(struct sockaddr *)&peer, &peer_address_size);
		liblog_debug(LAYER_LINK, "packet with %d bytes received.",
				packet_length);
		if (packet_length < 0) {
			liblog_error(LAYER_LINK, "error receiving data.");
			return;
		}
		if (packet_length < MIN_PACKET_LENGTH) {
			liblog_error(LAYER_LINK, "packet is too small to be valid.");
			continue;
		}
		/*liblog_debug(LAYER_LINK, "packet received.");*/
		switch(packet[0]) {
			case LLP_CONNECTION_REQUEST:
				llp_handle_connection_request(packet, packet_length, &peer);
				break;
			case LLP_CONNECTION_OK:
				llp_handle_connection_ok(packet, packet_length);
				break;
			case LLP_KEY_EXCHANGE:
				llp_handle_key_exchange(packet, packet_length);
				break;
			case LLP_DATA:
				llp_handle_data(packet, packet_length);
				break;
		}
	}
	return;
}
/******************************************************************************/
