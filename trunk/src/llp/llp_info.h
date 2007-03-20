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
 * @file llp_info.h Headers of procedures used to manage layer info.
 * @ingroup llp
 */
 
#ifndef _LLP_INFO_H_
#define _LLP_INFO_H_

/**
 * Initializes the info agregator.
 * 
 * @returns LLP_OK if no erros occurred, LLP_ERROR otherwise.
 */
int llp_info_initialize();
	
/*
 * Frees the resources allocated to the info module.
 */
void llp_info_finalize();

/**
 * Returns the number of active sessions (in ESTABLISHED state).
 * 
 * @returns number of active sessions.
 */
int llp_get_active_sessions_counter();

/**
 * Increments the number of active sessions by increment.
 * 
 * @param increment value to be added to the active session counter.
 */
void llp_add_active_sessions_counter(int increment);

#endif /* _LLP_INFO_H_ */
