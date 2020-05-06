// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "lib_context.h"
#include "pkcs11smw.h"
#include "util.h"
#include "trace.h"

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_RV ret;
	CK_C_INITIALIZE_ARGS_PTR pinit = pInitArgs;
	struct libcaps *libcaps;

	ret = libctx_create();
	if (ret != CKR_OK)
		return ret;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_NOT_INITIALIZED)
		return ret;

	libcaps = libctx_get_caps();
	if (!libcaps)
		return CKR_GENERAL_ERROR;

	if (!pinit) {
		libcaps->multi_thread = false;
		goto end_check;
	}

	/* Verify initialization argument validity */
	if (pinit->pReserved)
		return CKR_ARGUMENTS_BAD;

	/*
	 * if CKF_LIBRARY_CANT_CREATE_OS_THREADS is set in flags
	 * we can not use the OS new thread call
	 * return CKR_NEED_TO_CREATE_THREADS if not possible
	 */
	if (pinit->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) {
		DBG_TRACE("Can create thread with OS primitive");
		libcaps->use_os_thread = false;
	}

	if (util_check_ptrs_null(4, pinit->CreateMutex, pinit->DestroyMutex,
				 pinit->LockMutex, pinit->UnlockMutex)) {
		DBG_TRACE("All Mutex Function Pointers NULL");
		if (pinit->flags & CKF_OS_LOCKING_OK) {
			DBG_TRACE("Need to use OS Mutex primitives");
			/*
			 * Library will be called in multithreading
			 * context but call the OS multi-thread
			 * primitive must be done
			 * if not supported return CKR_CANT_LOCK
			 */
			libcaps->multi_thread = true;
			if (!libcaps->use_os_mutex)
				ret = CKR_CANT_LOCK;
		} else {
			libcaps->multi_thread = false;
		}
	} else if (util_check_ptrs_set(4, pinit->CreateMutex,
				       pinit->DestroyMutex, pinit->LockMutex,
				       pinit->UnlockMutex)) {
		DBG_TRACE("All Mutex Function Pointers SET");
		if (pinit->flags & CKF_OS_LOCKING_OK) {
			DBG_TRACE("Use OS Mutex or provided primitives");
			/*
			 * Multithread context must be handled
			 * using the pinit provided functions
			 * or OS multi-thread primitive
			 * if not supported return CKR_CANT_LOCK
			 *
			 * Preference is to use provided functions
			 */
			libcaps->multi_thread = true;
			libcaps->use_os_mutex = false;
		} else {
			/*
			 * Multithread context must be handled
			 * using the pinit provided functions
			 * if not supported return CKR_CANT_LOCK
			 */
			libcaps->multi_thread = true;
			libcaps->use_os_mutex = false;
		}
	} else {
		ret = CKR_ARGUMENTS_BAD;
	}

end_check:
	if ((libcaps->flags & LIBCAPS_MULTI_THREAD) && !libcaps->use_os_thread)
		ret = CKR_NEED_TO_CREATE_THREADS;

	DBG_TRACE("Multi-thread = %s",
		  libcaps->multi_thread ? "true" : "false");
	DBG_TRACE("Use OS Thread = %s",
		  libcaps->use_os_thread ? "true" : "false");
	DBG_TRACE("Use OS Mutex = %s",
		  libcaps->use_os_mutex ? "true" : "false");

	if (ret == CKR_CRYPTOKI_NOT_INITIALIZED) {
		ret = libctx_setup_mutex(pinit, libcaps);

		if (ret == CKR_OK)
			ret = libctx_set_initialized();
	}

	DBG_TRACE("return 0x%08lX", ret);
	return ret;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	CK_RV ret;

	if (pReserved)
		return CKR_ARGUMENTS_BAD;

	ret = libctx_destroy();

	return ret;
}
