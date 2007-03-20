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
 * @file lnp_id.h
 * @ingroup lnp
 */

#ifndef _LNP_ID_H_
#define _LNP_ID_H_

#include <openssl/rsa.h>

/** */
extern net_id_t my_id;

/** */
extern RSA *key_pair;

/** */
int lnp_id_initialize();

/** */
void lnp_id_finalize();

/** */
int lnp_get_public_key(u_char *data, int length);

#endif /* !_LNP_ID_H_ */
