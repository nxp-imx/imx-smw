// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023, 2026 NXP
 */

#include "lib_context.h"
#include "pkcs11smw.h"
#include "util.h"
#include "trace.h"

/**
 * C_Initialize() - Initialize the Cryptoki library.
 * @pInitArgs: [in] Pointer to initialization arguments or :c:macro:`NULL_PTR`.
 *
 * This function initializes the Cryptoki library and must be called before
 * any other Cryptoki function except C_GetInfo(), C_GetFunctionList(),
 * C_GetInterfaceList(), or C_GetInterface(). It sets up the library's internal
 * state, including multi-threading support and mutex handling based on the
 * provided initialization arguments.
 *
 * In the context of multiple appllications using the same Cryptoki library,
 * the C_Initialize() function must be called once.
 *
 * If @pInitArgs is not :c:macro:`NULL_PTR`, the argument is a pointer to a
 * :c:type:`CK_C_INITIALIZE_ARGS` structure.
 *
 * If the CKF_LIBRARY_CANT_CREATE_OS_THREADS flag in the flags field is set,
 * that indicates that application threads which are executing calls to the
 * Cryptoki library are not permitted to use the native operation system calls
 * to spawn off new threads. In other words, the library’s code may not create
 * its own threads.
 *
 * .. note::
 *    The library does not support the thread creation by itself.
 *
 * A call to C_Initialize() specifies one of four different ways to support
 * multi-threaded access via the value of the CKF_OS_LOCKING_OK flag in the
 * flags field and the values of the CreateMutex, DestroyMutex, LockMutex, and
 * UnlockMutex function pointer fields\:
 *
 *   #. If the flag isn’t set, and the function pointer fields aren’t supplied
 *      (i.e., they all have the value :c:macro:`NULL_PTR`), that means that the
 *      application won’t be accessing the Cryptoki library from multiple
 *      threads simultaneously.
 *   #. If the flag is set, and the function pointer fields aren’t supplied
 *      (i.e., they all have the value :c:macro:`NULL_PTR`), that means that the
 *      application will be performing multi-threaded Cryptoki access, and the
 *      library needs to use the native operating system primitives to ensure
 *      safe multi-threaded access. If the library is unable to do this,
 *      C_Initialize() returns with the value CKR_CANT_LOCK.
 *   #. If the flag isn’t set, and the function pointer fields are supplied
 *      (i.e., they all have non :c:macro:`NULL_PTR` values), that means that
 *      the application will be performing multi-threaded Cryptoki access, and
 *      the library needs to use the supplied function pointers for
 *      mutex-handling to ensure safe multi-threaded access. If the library is
 *      unable to do this, C_Initialize() returns with the value CKR_CANT_LOCK.
 *   #. If the flag is set, and the function pointer fields are supplied (i.e.,
 *      they all have non :c:macro:`NULL_PTR` values), that means that the
 *      application will be performing multi-threaded Cryptoki access, and the
 *      library needs to use either the native operating system primitives or
 *      the supplied function pointers for mutex-handling to ensure safe
 *      multi-threaded access. If the library is unable to do this,
 *      C_Initialize() returns with the value CKR_CANT_LOCK.
 *
 * If some, but not all, of the supplied function pointers to C_Initialize()
 * are non :c:macro:`NULL_PTR`, then C_Initialize returns with the value
 * CKR_ARGUMENTS_BAD.
 *
 * If @pInitArgs is :c:macro:`NULL_PTR`, the library assumes single-threaded
 * operation. Otherwise, the flags and function pointers in @pInitArgs determine
 * the threading model and mutex primitives to use.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Library is initialized.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pInitArgs->pReserved is not :c:macro:`NULL_PTR`.
 *      - Some, but not all, of the supplied function pointers are non
 *        :c:macro:`NULL_PTR`.
 *  - CKR_CANT_LOCK:
 *      Unable to acquire necessary locks for thread-safe operation.
 *  - CKR_CRYPTOKI_ALREADY_INITIALIZED:
 *      The library has already been initialized.
 *  - CKR_GENERAL_ERROR
 *  - CKR_NEED_TO_CREATE_THREADS:
 *      The library cannot create OS threads as required.
 */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_RV ret = CKR_OK;
	CK_C_INITIALIZE_ARGS_PTR pinit = pInitArgs;
	struct libcaps *libcaps = NULL;

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
			ret = libctx_initialized();
	}

	DBG_TRACE("return 0x%08lX", ret);
	return ret;
}

/**
 * C_Finalize() - Finalize the Cryptoki library.
 * @pReserved: Reserved for future use; must be :c:macro:`NULL_PTR`.
 *
 * This function cleans up the Cryptoki library and releases all resources
 * allocated during C_Initialize(). After calling this function, no other
 * Cryptoki functions (except C_Initialize()) may be called until the library
 * is re-initialized.
 *
 * If several applications are using Cryptoki, each one should call
 * C_Finalize().
 *
 * Return:
 *  - CKR_OK
 *  - CKR_ARGUMENTS_BAD:
 *      The @pReserved is not :c:macro:`NULL_PTR`.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - CKR_GENERAL_ERROR
 */
CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;

	if (!pReserved)
		ret = libctx_destroy();

	return ret;
}
