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
 * @file lnp_link.h Headers of routines used to manipulate the LNP socket.
 * @ingroup lnp
 */
 
#ifndef _LNP_LINK_H_
#define _LNP_LINK_H_ 

/**
 * Listens on the link layer.
 */
void lnp_listen_link();

/**
 * 
 */
u_char lnp_is_session_active(int session);

/**
 * 
 */
void lnp_link_connect_handler(int session);

/**
 * 
 */
void lnp_link_close_handler(int session);

/**
 * 
 */
int lnp_link_write(u_char *packet_data, int packet_length);


#endif /* !_LNP_LINK_H_ */
