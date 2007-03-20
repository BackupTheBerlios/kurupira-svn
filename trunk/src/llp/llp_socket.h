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
 * @file llp_socket.h Headers of routines used to manipulate the LLP socket.
 * @ingroup llp
 */
 
#ifndef _LLP_SOCKET_H_
#define _LLP_SOCKET_H_ 

/**
 * Defines that the LLP socket is not opened.
 */
#define LLP_CLOSED_SOCKET	(-1)

/**
* Socket used to send and receive packets.
*/
extern int llp_socket;
 
/**
 * Creates a UDP socket to handle traffic.
 * 
 * @param port port to be used in socket binding.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_create_socket(int port);

/**
 * Listens on the provided socket.
 */
void llp_listen_socket();

/*
 * Closes the socket being used;
 */
void llp_close_socket();

#endif /* !_LLP_SOCKET_H_ */
