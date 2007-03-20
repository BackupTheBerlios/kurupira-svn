/*
 * Copyright (C) 2006-07 The Kurupira Project
 * 
 * Kurupira is the legal property of its developers, whose names are not listed
 * here. Please refer to the COPYRIGHT file.
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
 * @file layers.h
 * 
 * Header that defines constants and structures related to all the layers.
 * 
 * @version $Header$
 * @ingroup kurupira
 */

#ifndef _LAYERS_H_
	#define _LAYERS_H_

	#include "layer_link.h"
	#include "layer_net.h"

	#define KURUPIRA_MTU			512

	/**
	 * Enumeration of layer identifiers.
	 */
	enum layers {
		LAYER_DAEMON, /**< daemon layer. */
		LAYER_LINK, /**< link layer. */
		LAYER_NET, /**< network layer. */
		LAYER_UNRELIABLE, /**< unreliable transport layer (like UDP). */
		LAYER_RELIABLE /**< reliable transport layer (like TCP). */
	};
	
	/*@{*/
	/**
	 * Layer descriptors.
	 */
	#define MODULE_DAEMON		"daemon"
	#define MODULE_LINK			"link"
	#define MODULE_NET			"net"
	#define MODULE_UNRELIABLE	"unreliable"
	#define MODULE_RELIABLE		"reliable"
	/*@}*/

#endif /*!_LAYERS_H_ */
