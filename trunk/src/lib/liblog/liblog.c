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
 * @file liblog.c
 * 
 * Implementation of the logging routines.
 * 
 * @version $Header$
 * @ingroup liblog
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>

#include "liblog.h"

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/**
 * Constants used in openlog function call.
 */
#define SYSLOG_OPTIONS (LOG_CONS | LOG_NDELAY)
#define SYSLOG_FACILITY LOG_USER

/**
 * Maximum length of a log message.
 */
#define LOG_LENGTH		256

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void liblog_init(const char *identifier) {
	openlog(identifier, SYSLOG_OPTIONS, SYSLOG_FACILITY);
}

void liblog_finish() {
	closelog();
}

void liblog_debug_complete(const char *module, const char *function,
		const char *file, int line, const char *format, ...) {
	char log_message[LOG_LENGTH];
	va_list argument_list;

	va_start(argument_list, format);
	vsnprintf(log_message, LOG_LENGTH, format, argument_list);
	va_end(argument_list);

	syslog(LOG_DEBUG, "DEBUG %s: %s() at %s,%d: %s", module, function, file,
			line, log_message);
}

void liblog_info(const char *module, const char *format, ...) {
	char log_message[LOG_LENGTH];
	va_list argument_list;

	va_start(argument_list, format);
	vsnprintf(log_message, LOG_LENGTH, format, argument_list);
	va_end(argument_list);

	syslog(LOG_INFO, "%s: %s", module, log_message);
}

void liblog_warn(const char *module, const char *format, ...) {
	char log_message[LOG_LENGTH];
	va_list argument_list;

	va_start(argument_list, format);
	vsnprintf(log_message, LOG_LENGTH, format, argument_list);
	va_end(argument_list);

	syslog(LOG_WARNING, "%s: %s", module, log_message);
}

void liblog_error(const char *module, const char *format, ...) {
	char log_message[LOG_LENGTH];
	va_list argument_list;

	va_start(argument_list, format);
	vsnprintf(log_message, LOG_LENGTH, format, argument_list);
	va_end(argument_list);

	syslog(LOG_ERR, "%s: %s", module, log_message);
}

void liblog_fatal(const char *module, const char *format, ...) {
	char log_message[LOG_LENGTH];
	va_list argument_list;

	va_start(argument_list, format);
	vsnprintf(log_message, LOG_LENGTH, format, argument_list);
	va_end(argument_list);

	syslog(LOG_CRIT, "%s: %s", module, log_message);
	fprintf(stderr, "FATAL: %s: %s\n", module, log_message);
}
