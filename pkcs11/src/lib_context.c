// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023 NXP
 */
#include <stdlib.h>

#include "lib_context.h"
#include "lib_device.h"
#include "pkcs11smw_config.h"

#include "trace.h"

/**
 * struct libctx - Library context
 * @initialized: Library is initialized
 * @caps: Library capabilities
 * @mutex: Mutex operations
 * @devices: Devices info/status
 */
struct libctx {
	bool initialized;
	struct libcaps caps;
	struct libmutex mutex;
	struct libdevice *devices;
};

static struct libctx *libctx;

static void initialize_caps(struct libcaps *caps)
{
	caps->flags = LIBCAPS_NO_FLAGS;

	/*
	 * Set the default library capabilities, in case
	 * no configuration specified during C_Initialize
	 */
	caps->use_os_mutex = false;
	caps->use_os_thread = false;
	caps->multi_thread = false;

#ifdef PKCS11_OS_MUTEX_SUPPORT
	caps->flags |= LIBCAPS_OS_MUTEX_SUPPORT;
	caps->use_os_mutex = true;
#endif
#ifdef PKCS11_OS_THREAD_SUPPORT
	caps->flags |= LIBCAPS_OS_THREAD_SUPPORT;
	caps->use_os_thread = true;
	/*
	 * TODO: Implement OS Thread primitives
	 */
#endif
#ifdef PKCS11_MULTI_THREAD
	caps->flags |= LIBCAPS_MULTI_THREAD;
	caps->multi_thread = true;
#endif

	DBG_TRACE("Libraries capabilities = 0x%08X", caps->flags);
}

struct libdevice *libctx_get_devices(void)
{
	if (!libctx)
		return NULL;

	return libctx->devices;
}

struct libcaps *libctx_get_caps(void)
{
	if (!libctx)
		return NULL;

	return &libctx->caps;
}

struct libmutex *libctx_get_mutex(void)
{
	if (!libctx)
		return NULL;

	return &libctx->mutex;
}

CK_RV libctx_initialized(void)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	if (!libctx)
		return ret;

	ret = libdev_initialize(&libctx->devices);
	if (ret == CKR_OK)
		libctx->initialized = true;

	return ret;
}

CK_RV libctx_get_initialized(void)
{
	if (!libctx)
		return CKR_GENERAL_ERROR;

	if (libctx->initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	return CKR_CRYPTOKI_NOT_INITIALIZED;
}

CK_RV libctx_setup_mutex(CK_C_INITIALIZE_ARGS_PTR pinit, struct libcaps *caps)
{
	if (caps->multi_thread && !caps->use_os_mutex && pinit) {
		libctx->mutex.create = pinit->CreateMutex;
		libctx->mutex.destroy = pinit->DestroyMutex;
		libctx->mutex.lock = pinit->LockMutex;
		libctx->mutex.unlock = pinit->UnlockMutex;
	} else if (caps->multi_thread && caps->use_os_mutex) {
		/*
		 * TODO: Implement OS Mutex primitives
		 */
		return CKR_FUNCTION_FAILED;
	} else if (!caps->multi_thread) {
		libctx->mutex.create = NULL;
		libctx->mutex.destroy = NULL;
		libctx->mutex.lock = NULL;
		libctx->mutex.unlock = NULL;
	}

	return CKR_OK;
}

CK_RV libctx_create(void)
{
	if (libctx && libctx->initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (!libctx)
		libctx = calloc(1, sizeof(*libctx));

	DBG_TRACE("allocated context @%p", libctx);
	if (!libctx)
		return CKR_HOST_MEMORY;

	initialize_caps(&libctx->caps);

	return CKR_OK;
}

CK_RV libctx_destroy(void)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	if (!libctx)
		return ret;

	if (!libctx->initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	ret = libdev_destroy(&libctx->devices);
	DBG_TRACE("Devices destroy return %lu", ret);
	if (ret != CKR_OK)
		return CKR_GENERAL_ERROR;

	free(libctx);
	libctx = NULL;

	return CKR_OK;
}
