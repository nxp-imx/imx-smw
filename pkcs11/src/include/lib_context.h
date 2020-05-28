/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __LIBCAPS_H__
#define __LIBCAPS_H__

#include "types.h"
#include "util.h"

#define LIBCAPS_OS_MUTEX_SUPPORT  BIT(3)
#define LIBCAPS_OS_THREAD_SUPPORT BIT(2)
#define LIBCAPS_MULTI_THREAD	  BIT(1)
#define LIBCAPS_NO_FLAGS	  BIT(0)

/**
 * libctx_get_devices() - returns the library devices
 *
 * Return: a pointer to the library devices @libdevice
 */
struct libdevice *libctx_get_devices(void);

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
 * @pinit: C_Initialize arguments
 * @caps : Library capabilities
 *
 * Function of the library capabilities, setup the mutex operations to
 * be either NULL, OS primitives, or application primitives.
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
