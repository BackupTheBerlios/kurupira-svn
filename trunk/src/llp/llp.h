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
 * @defgroup llp llp (Link Protocol)
 */

/** 
 * @file llp.h Interface of the LLP module.
 * @ingroup llp
 */

#ifndef _LLP_H_
#define _LLP_H_

#include <libfreedom/layer_net.h>

/**
 * Used to inform that a function ended properly.
 */
#define LLP_OK		LINK_OK
/**
 * Used to inform that a function ended with an error.
 */
#define LLP_ERROR	LINK_ERROR

/**
 * Major version of the LLP protocol. Implementations with the same major version
 * are compatible.
 */
#define LLP_MAJOR_VERSION 1

/**
 * Minor version of the LLP protocol. Used to express minor changes that don't 
 * affect compatibility.
 */
#define LLP_MINOR_VERSION 0

#endif /* !_LLP_H_ */
