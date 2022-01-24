/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_THREAD__H__
#define __UTIL_THREAD__H__

#include <pthread.h>

#include "util.h"

enum thread_state {
	STATE_NOT_INIT = 0,
	STATE_RUNNING,
	STATE_WAITING,
	STATE_EXITED,
	STATE_CANCELED
};

#define MAX_THR_NAME 20

/**
 * struct thread_data - Thread data object
 * @app: Application data
 * @parent_def: Parent's thread object definition
 * @status: Test status
 * @smw_status: SMW operation status
 * @subtest: Name of the subtest running
 * @id: Thread ID
 * @name: Thread name
 * @state: Thread state
 * @loop: Thread loop
 * @def: Thread test definition
 */
struct thread_data {
	struct app_data *app;
	struct json_object *parent_def;
	int status;
	enum smw_status_code smw_status;
	char *subtest;
	pthread_t id;
	char name[MAX_THR_NAME];
	enum thread_state state;
	int loop;
	struct json_object *def;
};

/**
 * struct thread_ends - Thread waiting all test threads
 * @app: Application data
 * @status: Test status
 * @id: Thread ID
 * @state: Thread state
 * @lock: Thread Mutex used to manage @cond
 * @cond: Thread Condition
 */
struct thread_ends {
	struct app_data *app;
	int status;
	pthread_t id;
	enum thread_state state;
	void *lock;
	void *cond;
};

/**
 * util_thread_init() - Initialize the thread list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_thread_init(struct llist **list);

/**
 * util_thread_start() - Start a new thread linked to the application.
 * @app: Application data
 * @obj: Thread JSON-C definition
 * @thr_num: Thread number in the application
 *
 * Function adds the new thread in the application list and
 * starts it.
 *
 * Return:
 * PASSED                  - Success.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -BAD_ARGS               - One of the argument is not correct.
 * -BAD_PARAM_TYPE         - Thread definition is not correct.
 */
int util_thread_start(struct app_data *app, struct json_object_iter *obj,
		      unsigned int thr_num);

/**
 * util_thread_get_ids() - Get the Thread ids from the thread name
 * @name: Thread name (test definition thread object)
 * @first: First thread id
 * @last: Last thread id
 *
 * The thread name must be "Thread x:y" or "Thread x"
 * The function extracts the first (x) and last (y) thread ids defined in the
 * thread name. If the thread name define a single thread id, the @last
 * thread id returned is equal to the @first thread id.
 *
 * Return:
 * PASSED                   - Success.
 * -FAILED                  - Last thread id is less than first thread id
 * -INTERNAL                - Thread name is badly defined
 * -BAD_ARGS                - One of the argument is not correct.
 */
int util_thread_get_ids(const char *name, unsigned int *first,
			unsigned int *last);

/**
 * util_get_thread_name() - Get the thread name
 * @app: Application data
 * @name: Thread name
 *
 * Function returns the active thread name register in the application
 * thread list.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the argument is not correct.
 */
int util_get_thread_name(struct app_data *app, const char **name);

/**
 * util_thread_ends_destroy() - Destroy the thread waiting ends of test threads
 * @app: Application data
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the argument is not correct.
 * -MUTEX_DESTROY          - Mutex destroy failure
 * -COND_DESTROY           - Mutex destroy failure
 */
int util_thread_ends_destroy(struct app_data *app);

/**
 * util_thread_ends_destroy() - Destroy the thread waiting ends of test threads
 * @app: Application data
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Operation failed
 * -BAD_ARGS               - One of the argument is invalid.
 * -INTERNAL               - Internal failure
 * -TIMEOUT                - Function timeout
 */
int util_thread_ends_wait(struct app_data *app);

/**
 * util_thread_log() - Log the given thread status
 * @thr: Thread data
 *
 * Log the thread name if multi-thread test, the subtest name if
 * a subtest is running, the error code string.
 * If the error code is a bad result, the SMW library status error.
 */
void util_thread_log(struct thread_data *thr);

#endif /* __UTIL_THREAD__H__ */
