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
 * @file kurud_main.c 
 * 
 * Entry point for kurud.
 * 
 * @version $Header$
 * @ingroup kurud
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <liblog.h>
#include <liberror.h>

#include "kurud.h"
#include "kurud_err.h"

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/*@{ */
/**
 * Version constant.
 */
#define KURUD_NAME 			"kurud"
#define KURUD_VERSION 		"v0.1"
#define COPYRIGHT 			"Copyright (C) 2006-07"
#define AUTHORS 			"The Kurupira Project " \
							"<iamscared[at]users.sourceforge.net>\n"
#define LICENSE 			"GNU General Public License (GPL) 2"
/*@} */

/**
 * Option descriptors used at getopt_long.
 */
static struct option options[] = {
	{"foreground", no_argument, NULL, 'f'},
	{"config", required_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'}
};

/**
 * Parameters used in getopt function.
 */
#define GETOPT_PARAMETERS 		"fc:hv"

/**
 * Shows usage for the program.
 */
void usage();

/**
 * Shows version information about the program.
 */
void version();

/*============================================================================*/
/* Main procedure.                                                            */
/*============================================================================*/

int main(int argc, char *argv[]) {
	char *config_file = NULL;
	char ch;
	int background = 1;

	while ((ch = getopt_long(argc, argv, GETOPT_PARAMETERS, options,
							NULL)) != -1) {
		switch (ch) {
			case 'f':
				background = 0;
				break;
			case 'c':
				config_file = optarg;
				break;
			case 'v':
				version();
				exit(0);
			case '?':
			case 'h':
			default:
				usage();
				exit(0);
		}
	}

	/* Running in background */
	if (background) {
		TRY(daemon(0, 0) == 0, FATAL(REASON_DAEMON_FORK));
	}
	TRY(kurud_init(config_file), FATAL(REASON_DAEMON_INIT));
	TRY(kurud_wait(), FATAL(REASON_DAEMON_RUN));
end:
	kurud_finish();
	liblog_info(MODULE_DAEMON, "daemon terminated.");
	return 0;
}

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

void usage() {
	printf("Usage: " KURUD_NAME " [options]\n");
	printf("The Kurupira daemon.\n");
	printf("\n");
	printf("Options:\n");
	printf("\n");
	printf("-f, --foreground        run daemon in foreground.\n");
	printf("-c, --config <file>     define configuration file.\n");
	printf("-h, --help              display this help screen.\n");
	printf("-v, --version           show version information and exit.\n");
}

void version() {
	printf(" Program: %s %s %s\n", KURUD_NAME, KURUD_VERSION, COPYRIGHT);
	printf(" License: %s\n", LICENSE);
	printf(" Authors: %s\n", AUTHORS);
}
