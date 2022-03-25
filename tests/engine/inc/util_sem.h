/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */
#ifndef __UTIL_SEM_H__
#define __UTIL_SEM_H__

#include <json.h>
#include <semaphore.h>
#include <stdbool.h>

#include "util_list.h"
#include "util_thread.h"

struct sem_obj {
	char *name;
	sem_t handle;
	bool init;
};

/**
 * util_sem_init() - Initialize the semaphore list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_sem_init(struct llist **list);

/**
 * util_sem_wait_before() - Wait a semaphore before operation
 * @thr: Thread data
 * @obj: JSON-C definition thread or operation.

 * Return:
 * PASSED                   - Success.
 * -BAD_PARAM_TYPE          - Semaphore definition not correct.
 * -INTERNAL                - Internal system error.
 * -BAD_ARGS                - One of the argument is not correct.
 * -FAILED                  - Failure
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 */
int util_sem_wait_before(struct thread_data *thr, struct json_object *obj);

/**
 * util_sem_wait_after() - Wait a semaphore after operation
 * @thr: Thread data
 * @obj: JSON-C definition thread or operation.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_PARAM_TYPE          - Semaphore definition not correct.
 * -INTERNAL                - Internal system error.
 * -BAD_ARGS                - One of the argument is not correct.
 * -FAILED                  - Failure
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 */
int util_sem_wait_after(struct thread_data *thr, struct json_object *obj);

/**
 * util_sem_post_before() - Post a semaphore before operation
 * @thr: Thread data
 * @obj: JSON-C definition thread or operation.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_PARAM_TYPE         - Semaphore definition not correct.
 * -INTERNAL               - Internal system error.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure.
 * -INTERNAL_OUT_OF_MEMORY - Allocation error
 */
int util_sem_post_before(struct thread_data *thr, struct json_object *obj);

/**
 * util_sem_post_after() - Post a semaphore after operation
 * @thr: Thread data
 * @obj: JSON-C definition thread or operation.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_PARAM_TYPE         - Semaphore definition not correct.
 * -INTERNAL               - Internal system error.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure.
 * -INTERNAL_OUT_OF_MEMORY - Allocation error
 */
int util_sem_post_after(struct thread_data *thr, struct json_object *obj);

/**
 * util_sem_post_to_before() - Post a semaphore to application(s) before
 * @app: Current application data
 * @obj: JSON-C definition application, thread or operation.
 *
 * Return:
 * PASSED                  - Success.
 * or any error code (see enum err_num)
 */
int util_sem_post_to_before(struct app_data *app, struct json_object *obj);

/**
 * util_sem_post_to_after() - Post a semaphore to application(s) after
 * @app: Current application data
 * @obj: JSON-C definition application, thread or operation.
 *
 * Return:
 * PASSED                  - Success.
 * or any error code (see enum err_num)
 */
int util_sem_post_to_after(struct app_data *app, struct json_object *obj);

/**
 * util_sem_ipc_post() - IPC request to post semaphore(s)
 * @app: Current application data
 * @sem_name: String list of the semaphore(s) to post
 */
void util_sem_ipc_post(struct app_data *app, const char *sem_name);

#endif /* __UTIL_SEM_H__ */
