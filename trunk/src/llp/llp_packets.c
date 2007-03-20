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
 * @file llp_packets.c Implementation of routines used to manipulate packets.
 * @ingroup llp
 */

#include <sys/socket.h>

#include <libfreedom/types.h>
#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>

#include "llp_packets.h"
#include "llp_sessions.h"
#include "llp_socket.h"
#include "llp.h"

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/	   

int llp_send_direct_packet(struct sockaddr_in *address, u_char *packet,
		int length) {
	int return_value;

	if (llp_socket == LLP_CLOSED_SOCKET) {
		liblog_error(LAYER_LINK, "llp module not initialized.");
		return LLP_ERROR;
	}

	return_value = sendto(llp_socket, packet, length, 0,
			(struct sockaddr *)address,	sizeof(struct sockaddr_in));	
	
	return (return_value < length ? LLP_ERROR : LLP_OK);
}
/******************************************************************************/
int llp_send_session_packet(int session, u_char *packet, int length) {

	return llp_send_direct_packet(&llp_sessions[session].address, packet,
			length);
}
/******************************************************************************/
