/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __LIB_MUTEX_H__
#define __LIB_MUTEX_H__

#include "types.h"

/**
 * libmutex_create() - Creates a mutex
 * @mutex - Pointer to the mutex to create
 *
 * Return:
 * CKR_HOST_MEMORY   - Memory allocation error
 * CKR_GENERAL_ERROR - No context available
 * CKR_OK            - Success
 */
CK_RV libmutex_create(CK_VOID_PTR_PTR mutex);

/**
 * libmutex_destroy() - Destroys a mutex
 * @mutex - Pointer to the mutex to destroy
 *
 * Return:
 * CKR_MUTEX_BAD     - Mutex not correct
 * CKR_HOST_MEMORY   - Memory error
 * CKR_GENERAL_ERROR - No context available
 * CKR_OK            - Success
 */
CK_RV libmutex_destroy(CK_VOID_PTR_PTR mutex);

/**
 * libmutex_lock() - Wait and locks a mutex
 * @mutex - Pointer to the mutex to lock
 *
 * Return:
 * CKR_MUTEX_BAD     - Mutex not correct
 * CKR_HOST_MEMORY   - Memory error
 * CKR_GENERAL_ERROR - No context available
 * CKR_OK            - Success
 */
CK_RV libmutex_lock(CK_VOID_PTR mutex);

/**
 * libmutex_unlock() - Unlocks a mutex
 * @mutex - Pointer to the mutex to unlock
 */
void libmutex_unlock(CK_VOID_PTR mutex);

#endif /* __LIB_MUTEX_H__ */
