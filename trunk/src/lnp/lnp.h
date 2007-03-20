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
 * @defgroup lnp lnp (Network Protocol)
 */

/** 
 * @file lnp.h Interface of the LNP module.
 * @ingroup lnp
 */

#ifndef _LNP_H_
#define _LNP_H_

#include <libfreedom/layer_net.h>

/**
 * Used to inform that a function ended properly.
 */
#define LNP_OK		0
/**
 * Used to inform that a function ended with an error.
 */
#define LNP_ERROR	(-1)

/**
 * Major version of the LNP protocol. Implementations with the same major version
 * are compatible.
 */
#define LNP_MAJOR_VERSION 1

/**
 * Minor version of the LNP protocol. Used to express minor changes that don't 
 * affect compatibility.
 */
#define LNP_MINOR_VERSION 0

/**
 * 
 */
#define LNP_PROTOCOL_RELIABLE 		1

/**
 * 
 */
#define LNP_PROTOCOL_UNRELIABLE 	2

/*
 * Object that represents the interface of the link layer used by this module.
 */
extern layer_link_t *link_interface;

#endif /* !_LNP_H_ */
