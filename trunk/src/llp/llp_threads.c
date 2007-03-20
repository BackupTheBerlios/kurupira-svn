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
 * @file llp_threads.c Implementations of routines used to handle the LLP module
 * 		threads.
 * @ingroup llp
 */
 
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>

#include <libfreedom/layer_link.h>
#include <libfreedom/liblog.h>
#include <libfreedom/layers.h>

#include "llp.h"
#include "llp_config.h"
#include "llp_sessions.h"
#include "llp_nodes.h"
#include "llp_handshake.h"
#include "llp_data.h"
#include "llp_socket.h"
 
/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Initial delay between the timeout_thread and silence_thread
 * (in LLP_TIME_TICKs).
 */
#define TIMEOUT_THREAD_DELAY	(0.5)

/* 
 * Time that the timeout thread will sleep (in LLP_TIME_TICKs).
 */
#define TIMEOUT_THREAD_SLEEP	(1)

/* 
 * Time that the silence thread will sleep (in LLP_TIME_TICKs).
 */
#define SILENCE_THREAD_SLEEP	(1)

/* 
 * Time that the monitor thread will sleep (in LLP_TIME_TICKS).
 */
#define MONITOR_THREAD_SLEEP	(10)

/*
 * Thread that will listen in UDP socket.
 */
static pthread_t listen_thread;

/*
 * Thread that will do session timeout and expiration management
 */
static pthread_t timeout_thread;

/*
 * Thread that will do keep-alive management.
 */
static pthread_t silence_thread;

/*
 * Thread that will monitor cache rate and number of active sessions.
 */
static pthread_t monitor_thread;

/*
 * Mutex used by condition variable timeout_condition.
 */
static pthread_mutex_t timeout_mutex;

/*
 * Mutex used by condition variable silence_condition.
 */
static pthread_mutex_t silence_mutex;

/*
 * Mutex used by condition variable monitor_condition.
 */
static pthread_mutex_t monitor_mutex;

/*
 * Contidion variable used by timeout_thread
 */
static pthread_cond_t timeout_condition;

/*
 * Condition variable used by silence_thread.
 */
static pthread_cond_t silence_condition;

/*
 * Condition variable used by monitor_thread.
 */
static pthread_cond_t monitor_condition;

static int finish_execution = 0;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * Function to be executed by the listen_thread.
 */
static void *run_listen_socket();

/*
 * Function to be executed by timeout_thread.
 */
static void *timer_handle_timeouts();

/*
 * Function to be executed by silence_thread.
 */
static void *timer_handle_silence();

/*
 * Function to be executed by monitor_thread.
 */
static void *timer_monitor();

/*
 * Computes the time that a thread must sleep.
 */
static inline void thread_sleep(float sleep, pthread_cond_t *condition,
		pthread_mutex_t *mutex);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_create_threads() {

	if (pthread_mutex_init(&timeout_mutex, NULL)) {
		liblog_error(LAYER_LINK, "error creating mutex: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	if (pthread_mutex_init(&silence_mutex, NULL)) {
		liblog_error(LAYER_LINK, "error creating mutex: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	if (pthread_mutex_init(&monitor_mutex, NULL)) {
		liblog_error(LAYER_LINK, "error creating mutex: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	if (pthread_cond_init(&timeout_condition, NULL)) {
		liblog_error(LAYER_LINK, "error creating condition variable: %s.",
				strerror(errno));
		return LLP_ERROR;
	}

	if (pthread_cond_init(&silence_condition, NULL)) {
		liblog_error(LAYER_LINK, "error creating condition variable: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	
	if (pthread_cond_init(&monitor_condition, NULL)) {
		liblog_error(LAYER_LINK, "error creating condition variable: %s.",
				strerror(errno));
		return LLP_ERROR;
	}

	/* Thread to listen packets. */
	if (pthread_create(&listen_thread, NULL, run_listen_socket, NULL)) {
		liblog_error(LAYER_LINK, "error creating thread: %s.", strerror(errno));
		return LLP_ERROR;
	}

	/* Thread to handle session timeout and expiration. */
	if (pthread_create(&timeout_thread, NULL, timer_handle_timeouts, NULL)) {
		liblog_error(LAYER_LINK, "error creating thread: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	/* Thread to handle session keep-alive. */
	if (pthread_create(&silence_thread, NULL, timer_handle_silence, NULL)) {
		liblog_error(LAYER_LINK, "error creating thread: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	/* Thread to monitor cache fill rate and number of connections. */
	if (pthread_create(&monitor_thread, NULL, timer_monitor, NULL)) {
		liblog_error(LAYER_LINK, "error creating thread: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	finish_execution = 0;
	
	return LLP_OK;
}
/******************************************************************************/
void llp_destroy_threads() {
	
	finish_execution = 1;
	
	pthread_cond_broadcast(&silence_condition);
	pthread_cond_broadcast(&timeout_condition);
	pthread_cond_broadcast(&monitor_condition);

	pthread_join(silence_thread, NULL);
	pthread_join(timeout_thread, NULL);
	pthread_join(monitor_thread, NULL);

	pthread_mutex_destroy(&silence_mutex);
	pthread_mutex_destroy(&timeout_mutex);
	pthread_mutex_destroy(&monitor_mutex);
	pthread_cond_destroy(&silence_condition);
	pthread_cond_destroy(&timeout_condition);
	pthread_cond_destroy(&monitor_condition);
}

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

void *run_listen_socket() {

	llp_listen_socket();
	pthread_exit(NULL);
		
	return LLP_OK;
}
/******************************************************************************/
void *timer_handle_timeouts() {
	
	/* Initial delay between threads. */
	pthread_mutex_lock(&timeout_mutex);
	thread_sleep(TIMEOUT_THREAD_SLEEP, &timeout_condition, &timeout_mutex);

	while (1) {
		if (finish_execution == 1) {
			pthread_exit(NULL);
		}
		llp_handle_timeouts();
		thread_sleep(TIMEOUT_THREAD_SLEEP, &timeout_condition,
				&timeout_mutex);
    }

	return LLP_OK;
}
/******************************************************************************/
void *timer_handle_silence() {
	
	pthread_mutex_lock(&silence_mutex);
	while (1) {
		if (finish_execution == 1) {
			pthread_exit(NULL);
		}
		llp_handle_silence();
		thread_sleep(SILENCE_THREAD_SLEEP, &silence_condition, 
				&silence_mutex);
    }
    
    return LLP_OK;
}
/******************************************************************************/
void *timer_monitor() {
	
	pthread_mutex_lock(&monitor_mutex);
	while (1) {
		if (finish_execution == 1) {
			pthread_exit(NULL);
		}
		llp_handle_nodes();
		llp_handle_connections();
		thread_sleep(MONITOR_THREAD_SLEEP, &monitor_condition,
				&monitor_mutex);
    }
    
    return LLP_OK;
}
/******************************************************************************/
void thread_sleep(float sleep, pthread_cond_t *condition,
		pthread_mutex_t *mutex) {
	struct timeval time;
	struct timespec delay;

	gettimeofday(&time, NULL);

	delay.tv_nsec = time.tv_usec * 1000 +
				(((long)(LLP_TIME_TICK*sleep)) % 1000) * 1000 * 1000;

	/* If nsec is bigger than a second. */
	if (delay.tv_nsec > 1000000000) {
		delay.tv_sec = time.tv_sec + delay.tv_nsec / 1000000000 +
				((long)(LLP_TIME_TICK*sleep)) / 1000;
		delay.tv_nsec %= 1000000000;

	} else {
		delay.tv_sec = time.tv_sec + (LLP_TIME_TICK*sleep) / 1000;
	}
	
	pthread_cond_timedwait(condition, mutex, &delay);
}
/******************************************************************************/
