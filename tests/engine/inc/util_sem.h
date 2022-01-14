/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */
#ifndef __UTIL_SEM_H__
#define __UTIL_SEM_H__

#include <json.h>

#include "util_list.h"
#include "util_thread.h"

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
 *
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

#endif /* __UTIL_SEM_H__ */
