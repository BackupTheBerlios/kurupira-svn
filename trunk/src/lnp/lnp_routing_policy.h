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
 * @file lnp_routing_policy.h
 * @ingroup lnp
 */

#ifndef _LNP_ROUTING_POLICY_H_
#define _LNP_ROUTING_POLICY_H_

#define LNP_ROUTE_RECEIVE (-1)
#define LNP_ROUTE_BACK (-2)
#define LNP_ROUTE_BACK_WITH_ERROR (-3)
#define LNP_ROUTE_BROADCAST (-4)
#define LNP_ROUTE_DROP (-5)

/**
 * @return the session to redirect this packet, or a number less then zero,
 * 		indicating an specific action.
 */
int lnp_routing_handle(net_id_t id_from, net_id_t id_to, u_char *packet_hash, 
		u_char packet_flags, int session_from);

#endif /* !_LNP_ROUTING_POLICY_H_ */
