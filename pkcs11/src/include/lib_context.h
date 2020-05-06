/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __LIBCAPS_H__
#define __LIBCAPS_H__

#include "pkcs11smw.h"
#include "util.h"

/**
 * struct libmutex - Mutex functions
 * @create: Create a mutex
 * @destroy: Destroy a mutex
 * @lock: Lock a mutex
 * @unlock: Unlock a mutex
 */
struct libmutex {
	CK_CREATEMUTEX create;
	CK_DESTROYMUTEX destroy;
	CK_LOCKMUTEX lock;
	CK_UNLOCKMUTEX unlock;
};

/**
 * struct libcaps - Library capabilities
 * @flags: Capabilities flags
 * @use_os_thread: Library can create its own thread with OS primitive
 * @use_os_mutex: OS Mutex Primitive can be used
 * @multi_thread: Multi-threading is enabled
 */
struct libcaps {
	unsigned int flags;
	bool use_os_thread;
	bool use_os_mutex;
	bool multi_thread;
};

#define LIBCAPS_OS_MUTEX_SUPPORT  BIT32(3)
#define LIBCAPS_OS_THREAD_SUPPORT BIT32(2)
#define LIBCAPS_MULTI_THREAD	  BIT32(1)
#define LIBCAPS_NO_FLAGS	  BIT32(0)

/**
 * struct libctx - Library context
 * @initialized: Library is initialized
 * @caps: Library capabilities
 * @mutex: Mutex operations
 */
struct libctx {
	bool initialized;
	struct libcaps caps;
	struct libmutex mutex;
};

/**
 * libctx_get_caps() - returns the library capabilities
 *
 * Return: a pointer to the library capabilities @libcaps
 */
struct libcaps *libctx_get_caps(void);

/**
 * libctx_set_initialized - set the context initialized status
 *
 * Return:
 * CKR_GENERAL_ERROR - No context available
 * CKR_OK            - Success
 */
CK_RV libctx_set_initialized(void);

/**
 * libctx_setup_mutex() - Setup the mutex operations
 *
 * Function of the library capabilities, setup the mutex operations to
 * be either NULL, OS primitives, or application primitives.
 *
 * @pinit: C_Initialize arguments
 * @caps : Library capabilities
 *
 * Return:
 * CKR_FUNCTION_FAILED - Can't support this option
 * CKR_OK              - Success
 */
CK_RV libctx_setup_mutex(CK_C_INITIALIZE_ARGS_PTR pinit, struct libcaps *caps);

/**
 * libctx_get_initialized - returns if context initialized or not
 *
 * Return:
 * CKR_CRYPTOKI_ALREADY_INITIALIZED - Context initialized
 * CKR_CRYPTOKI_NOT_INITIALIZED     - Context not initialized
 * CKR_GENERAL_ERROR                - No context available
 */
CK_RV libctx_get_initialized(void);

/**
 * libctx_create() - creates the library context
 *
 * Allocate the library context and iniatializes the default capabilities.
 *
 * Return:
 * CKR_CRYPTOKI_ALREADY_INITIALIZED - Context already initialized
 * CKR_HOST_MEMORY                  - Allocation error
 * CKR_OK                           - Success
 */
CK_RV libctx_create(void);

/**
 * libctx_destroy() - destroys the library context
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED - Context present but not initialized
 * CKR_GENERAL_ERROR            - No context available
 * CKR_OK                       - Success
 */
CK_RV libctx_destroy(void);

#endif /* __LIBCAPS_H__ */
