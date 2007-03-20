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
 * @file lnp_collision_table.h
 * @ingroup lnp
 */

#ifndef _LNP_COLLISION_TABLE_H_
#define _LNP_COLLISION_TABLE_H_

/**
 * 
 */
#define NO_COLLISION (-1)

/**
 * 
 */
#define COLLISION_HASH_LENGTH 20

/**
 * @return NO_COLLISION if no colision was detected. Otherwise, the session
 * from which this packet was last sent.
 */
int lnp_handle_collision(u_char *packet_hash, u_char packet_flags);

#endif /* !_LNP_COLLISION_TABLE_H_ */
