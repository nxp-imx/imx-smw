/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_COND_H__
#define __UTIL_COND_H__

/**
 * util_cond_create() - Create a new condition object
 *
 * Return:
 * Pointer to the new condition object if success,
 * Otherwise NULL.
 */
void *util_cond_create(void);

/**
 * util_cond_destroy() - Destroy a condition object
 * @cond: Condition object
 *
 * Function frees the condition object and reset @cond to NULL.
 *
 * Return:
 * PASSED          - Operation success
 * -COND_DESTROY   - Mutex destroy failure
 * -BAD_ARGS       - One of the argument is invalid.
 */
int util_cond_destroy(void **cond);

/**
 * util_cond_signal() - Signal a condition object
 * @cond: Condition object
 *
 * Return:
 * PASSED          - Operation success
 * -FAILED         - Operation failed
 * -BAD_ARGS       - One of the argument is invalid.
 */
int util_cond_signal(void *cond);

/**
 * util_cond_wait() - Wait for a condition object
 * @cond: Condition object
 * @mutex: Mutex assiociated to the object
 * @timeout: Timeout in seconds to wait.
 *
 * The function locks the @mutex and then wait for the condition.
 * thread condition wait function automatically release the @mutex.
 *
 * Before exits, the @mutex is unlock.
 *
 * Return:
 * PASSED          - Operation success
 * -FAILED         - Operation failed
 * -BAD_ARGS       - One of the argument is invalid.
 * -INTERNAL       - Internal failure
 * -TIMEOUT        - Function timeout
 */
int util_cond_wait(void *cond, void *mutex, unsigned int timeout);

#endif /* __UTIL_COND_H__ */
