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
 * @defgroup liberror liberror, the error management library
 */

/**
 * @file liberror.h
 * 
 * Error codes and interface of error management functions.
 * 
 * @version $Header$
 * @ingroup liberror
 */

#ifndef _LIBERROR_H_
	#define _LIBERROR_H_

	/**
	 * Maximum length of a error message.
	 */
	#define ERROR_LENGTH	256

	/**
	 * Type that describes a module context.
	 */
	typedef struct {
		int code; /**< The code returned by the last function. */
		char reason[ERROR_LENGTH]; /**< The reason that caused the error. */
	} error_t;

	/**
	 * Treats an error using predefined constants. The symbols ERROR_CONTEXT,
	 * ERROR_CODE, ERROR_TARGET, ERROR_PRINT and ERROR_CALBACK must be defined
	 * prior to call. The symbol ERROR_CONTEXT can be NULL if the module using
	 * the library does not have a context object.
	 * 
	 * @param[in] REASON    - the reason that caused the error
	 */
	#define ERR(REASON)														\
	ERR_HANDLER(ERROR_CONTEXT, ERROR_CODE, ERROR_PRINT, ERROR_CALLBACK, REASON);

	/**
	 * Treats an error using predefined constants. The symbols ERROR_CONTEXT,
	 * ERROR_CODE, ERROR_TARGET, ERROR_PRINT and ERROR_CALBACK must be defined
	 * prior to call. The symbol ERROR_CONTEXT can be NULL if the module using
	 * the library does not have a context object.
	 * 
	 * @param[in] REASON    - the reason that caused the error
	 * @param[in] ...       - the arguments matching REASON as format string
	 */
	#define ERROR(REASON, ...)												\
	ERROR_HANDLER(ERROR_CONTEXT, ERROR_CODE, ERROR_PRINT_ALL, ERROR_CALLBACK, REASON, ##__VA_ARGS__);

	/**
	 * Treats a fatal error. The symbols ERROR_CONTEXT, ERROR_CODE,
	 * ERROR_TARGET, ERROR_PRINT and ERROR_CALBACK must be defined prior to
	 * call. The symbol ERROR_CONTEXT can be NULL if the module using the 
	 * library does not have a context object.
	 * 
	 * @param[in] REASON    - the reason that caused the error
	 */
	#define FATAL(REASON)													\
	ERR_HANDLER(ERROR_CONTEXT, ERROR_CODE, ERROR_PRINT_FATAL, ERROR_CALLBACK, REASON);

	/**
	 * The default context to use if an error occurs.
	 */
	#define ERROR_CONTEXT 		NULL

	/**
	 * The default target to jump if an error occurs.
	 */
	#define ERROR_TARGET 		none

	/**
	 * The default value returned by functions in case of errors.
	 */
	#define ERROR_CODE			0

	/**
	 * The default printing function to use if an error occurs.
	 */
	#define ERROR_PRINT			liberror_simple_err

	/**
	 * The default printing function to use if an error occurs.
	 */
	#define ERROR_PRINT_ALL		liberror_simple_error

	/**
	 * The default printing function to use if an error occurs.
	 */
	#define ERROR_PRINT_FATAL	liberror_fatal_err

	/**
	 * The default error callback to use if an error occurs.
	 */
	#define ERROR_CALLBACK /* empty */

	/**
	 * Prints the error message and jumps to the desired label.
	 * 
	 * @param[in,out] CONTEXT   - the module context
	 * @param[in] CODE          - the error returned by the last function called
	 * @param[in] PRINT         - the function used to print the error
	 * @param[in] CALLBACK      - an optional additional function to call
	 * @param[in] REASON        - the reason that caused the error
	 */
	#define ERR_HANDLER(CONTEXT, CODE, PRINT, CALLBACK, REASON)				\
		PRINT(CONTEXT, CODE, REASON);										\
		CALLBACK;

	/**
	 * Prints the error message and jumps to the desired label.
	 * 
	 * @param[in,out] CONTEXT   - the module context
	 * @param[in] CODE          - the error returned by the last function called
	 * @param[in] PRINT         - the function used to print the error
	 * @param[in] CALLBACK      - an optional additional function to call
	 * @param[in] REASON        - the reason that caused the error
	 * @param[in] ...           - the arguments matching REASON as format string 
	 */
	#define ERROR_HANDLER(CONTEXT, CODE, PRINT, CALLBACK, REASON, ...)		\
		PRINT(CONTEXT, CODE, REASON, ##__VA_ARGS__);						\
		CALLBACK;

	/**
	 * Asserts the correct functioning of a function.
	 * 
	 * @param[in] FUNCTION  - the function to execute
	 * @param[in] HANDLER   - the error handling function
	 */
	#define TRY(FUNCTION, HANDLER)											\
	if (ERROR_CODE == (FUNCTION)) {											\
		HANDLER;															\
	}
	
	/**
	 * Asserts a condition.
	 * 
	 * @param[in] CONDITION - the condition to verify
	 * @param[in] HANDLER	- the error handling function
	 */
	#define ASSERT(CONDITION, HANDLER)										\
	if (!(CONDITION)) {														\
		HANDLER;															\
	}
	
	/**
	 * Prints the error message with little information.
	 * 
	 * @param[out] CONTEXT  - the module context
	 * @param[in] CODE      - the error returned by the last function called
	 * @param[in] REASON    - the reason that caused the error
	 */
	#define liberror_simple_err(CONTEXT, CODE, REASON)						\
		liberror_simple(CONTEXT, CODE, REASON)

	/**
	 * Prints the error message with little information.
	 * 
	 * @param[out] CONTEXT  - the module context
	 * @param[in] CODE      - the error returned by the last function called
	 * @param[in] REASON    - the reason that caused the error
	 * @param[in] ...       - the arguments matching REASON as format string
	 */
	#define liberror_simple_error(CONTEXT, CODE, REASON, ...)				\
		liberror_simple(CONTEXT, CODE, REASON, ##__VA_ARGS__)

	/**
	 * Prints the error message with detailed information.
	 * 
	 * @param[out] CONTEXT  - the module context
	 * @param[in] CODE      - the error returned by the last function called
	 * @param[in] REASON    - the reason that caused the error
	 */
	#define liberror_complete_err(CONTEXT, CODE, REASON)					\
		liberror_complete(CONTEXT, __func__, __FILE__, __LINE__, CODE, REASON)

	/**
	 * Prints the error message with detailed information.
	 * 
	 * @param[out] CONTEXT  - the module context
	 * @param[in] CODE      - the error returned by the last function called
	 * @param[in] REASON    - the reason that caused the error
	 * @param[in] ...       - the arguments matching REASON as format string
	 */
	#define liberror_complete_error(CONTEXT, CODE, REASON, ...)				\
		liberror_complete(CONTEXT, __func__, __FILE__, __LINE__, CODE, REASON, ##__VA_ARGS__)

	/**
	 * Prints the fatal error message with detailed information.
	 * 
	 * @param[out] CONTEXT  - the module context
	 * @param[in] CODE      - the error returned by the last function called
	 * @param[in] REASON    - the reason that caused the error
	 */
	#define liberror_fatal_err(CONTEXT, CODE, REASON)					\
		liberror_complete(CONTEXT, __func__, __FILE__, __LINE__, CODE, "FATAL: " REASON)

	/**
	 * Prints the error message with little information.
	 * 
	 * @param[out] context  - the library context
	 * @param[in] code      - the error returned by the last function called
	 * @param[in] reason    - the reason that caused the error
	 * @param[in] ...       - the arguments matching reason as format string
	 */
	void liberror_simple(error_t *context, int code, const char *reason, ...);

	/**
	 * Prints the error message with detailed information.
	 * 
	 * @param[out] context  - the library context
	 * @param[in] function  - the function where the error occurred
	 * @param[in] file      - the source file where the error occurred
	 * @param[in] line      - the line in the file where the error occurred
	 * @param[in] code      - the error returned by the last function called
	 * @param[in] reason    - the reason that caused the error
	 * @param[in] ...       - the arguments matching reason as format string
	 */
	void liberror_complete(error_t *context, const char *function,
		const char *file, int line, int code, const char *reason, ...);

#endif /* !_LIBERROR_H_ */
