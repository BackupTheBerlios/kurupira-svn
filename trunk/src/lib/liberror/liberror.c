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
 * @file liberror.c
 * 
 * Implementation of error management routines.
 * 
 * @version $Header$
 * @ingroup liberror
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "liberror.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void liberror_simple(error_t *context, int code, const char *reason,
		...) {
	char message[ERROR_LENGTH];
	va_list argument_list;

	va_start(argument_list, reason);
	vsnprintf(message, ERROR_LENGTH, reason, argument_list);
	va_end(argument_list);

	if (context != NULL) {
		context->code = code;
		strncpy(context->reason, message, ERROR_LENGTH);
	}
	fprintf(stderr, "error: %s.\n", message);
}

void liberror_complete(error_t *context, const char *function,
	const char *file, int line, int code, const char *reason, ...) {
	char message[ERROR_LENGTH];
	va_list argument_list;

	va_start(argument_list, reason);
	vsnprintf(message, ERROR_LENGTH, reason, argument_list);
	va_end(argument_list);

	if (context != NULL) {
		context->code = code;
		strncpy(context->reason, message, ERROR_LENGTH);
	}
	fprintf(stderr, "error in %s() at %s,%d: %s.\n", function, file, line,
			message);
}
