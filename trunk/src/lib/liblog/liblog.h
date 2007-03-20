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
 * @defgroup liblog liblog, the logging facility
 */

/**
 * @file liblog.h
 * 
 * Interface of the logging routines.
 * 
 * @version $Header$
 * @ingroup liblog
 */

#ifndef _LIBLOG_H_
	#define _LIBLOG_H_

	#ifdef WITH_DEBUG
		/**
		 * Logs the message sent by the layer identified with debug priority.
		 * This macro should be used like the other log functions:
		 * 
		 *      <tt>liblog_debug(module, format, ...);</tt>
		 * 
		 * @param[in] MODULE    - the module identifier
		 * @param[in] FORMAT    - the format string
		 * @param[in] ...       - the list of arguments matching format
		 */
		#define liblog_debug(MODULE, ...) 								\
			liblog_debug_complete										\
				(MODULE, __func__, __FILE__, __LINE__, ##__VA_ARGS__)
		
		void liblog_debug_complete(const char *module, const char *function,
		const char *file, int line, const char *format, ...);
	#else /* WITH_DEBUG */
		#define liblog_debug(...) /* empty */
	#endif /* !WITH_DEBUG */

	/**
	 * Initializes the logging system. If the logging is already active,
	 * subsequent calls to this function won't allocate any new resources.
	 * 
	 * @param[in] identifier    - the log identifier
	 */
	void liblog_init(const char *identifier);

	/**
	 * Terminates the logging system. This function also frees the resources
	 * being used by the logging system.
	 */
	void liblog_finish();

	/**
	 * Logs the message sent by the module identified with information priority.
	 * 
	 * @param[in] module        - the module identifier
	 * @param[in] format        - the format string
	 * @param[in] ...           - the list of arguments matching format
	 */
	void liblog_info(const char *module, const char *format, ...);

	/**
	 * Logs the message sent by the module identified with warning priority.
	 * 
	 * @param[in] module        - the module identifier
	 * @param[in] format        - the format string
	 * @param[in] ...           - the list of arguments matching format
	 */
	void liblog_warn(const char *module, const char *format, ...);

	/**
	 * Logs the mesage sent by the module identified with error priority.
	 * 
	 * @param[in] module        - the module identifier
	 * @param[in] format        - the format string
	 * @param[in] ...           - the list of arguments matching format
	 */
	void liblog_error(const char *module, const char *format, ...);

	/**
	 * Logs the message sent by the module identified with fatal priority.
	 * 
	 * @param[in] module        - the module identifier
	 * @param[in] format        - the format string
	 * @param[in] ...           - the list of arguments matching format
	 */
	void liblog_fatal(const char *module, const char *format, ...);

#endif /*!_LIBLOG_H_ */
