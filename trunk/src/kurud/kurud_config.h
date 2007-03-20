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
 * @file kurud_config.h
 * 
 * Interface of the configuration routines for the daemon.
 * 
 * @version $Header$
 * @ingroup kurud
 */

#ifndef _KURUD_CONFIG_H_
	#define _KURUD_CONFIG_H_

	/**
	 * Reads the configuration file looking for configuration parameters.
	 * If the file name argument is NULL, the default configuration file is used.
	 * 
	 * @param[in] config_file   - the configuration file to load
	 * @return KURUD_OK if successful, KURUD_ERROR otherwise.
	 */
	int kurud_configure(char *config_file);

	/**
	 * Frees the memory allocated for configuration storage.
	 */
	void kurud_unconfigure();

	/**
	 * Returns the filename of the lock file.
	 */
	char *kurud_get_lock_file();

	/**
	 * Returns the filename of the console interface file.
	 */
	char *kurud_get_console_file();

	/**
	 * Returns the filename of one of the modules that implements a layer.
	 * 
	 * @param[in] layer         	- the layer
	 * @return filename of the given module.
	 */
	char *kurud_get_module_file(int layer);

	/**
	 * Returns the configuration filename of one of the modules.
	 * 
	 * @param[in] layer			- the layer
	 * @return configuration filename of the given module.
	 */
	char *kurud_get_module_config(int layer);

#endif /* !_KURUD_CONFIG_H_ */
