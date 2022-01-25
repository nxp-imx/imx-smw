/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_MUTEX_H__
#define __UTIL_MUTEX_H__

/**
 * util_mutex_create() - Create a new mutex object
 *
 * Return:
 * Pointer to the new mutex object if success,
 * Otherwise NULL.
 */
void *util_mutex_create(void);

/**
 * util_mutex_destroy() - Destroy a mutex object
 * @mutex: Mutex object
 *
 * Function frees the mutex object and reset @mutex to NULL.
 *
 * Return:
 * PASSED          - Operation success
 * -MUTEX_DESTROY  - Mutex destroy failure
 * -BAD_ARGS       - One of the argument is invalid.
 */
int util_mutex_destroy(void **mutex);

/**
 * util_mutex_lock() - Lock a mutex object
 * @mutex: Mutex object
 */
void util_mutex_lock(void *mutex);

/**
 * util_mutex_unlock() - Unlock a mutex object
 * @mutex: Mutex object
 */
void util_mutex_unlock(void *mutex);

#endif /* __UTIL_MUTEX_H__ */
