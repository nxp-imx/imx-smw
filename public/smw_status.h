/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __SMW_STATUS_H__
#define __SMW_STATUS_H__

/**
 * enum smw_status_code - Security Middleware status codes
 *
 * @SMW_STATUS_OK: Function returned successfully.
 * @SMW_STATUS_UNKNOWN_NAME: One of the string name arguments is not valid.
 * @SMW_STATUS_UNKNOWN_ID: One of the identifier arguments is not valid.
 * @SMW_STATUS_ALLOC_FAILURE: Internal allocation failure.
 * @SMW_STATUS_INVALID_PARAM: One of the argument parameter is not valid.
 * @SMW_STATUS_VERSION_NOT_SUPPORTED: Argument version not compatible.
 * @SMW_STATUS_SUBSYSTEM_LOAD_FAILURE: Load of the Secure Subsystem failed.
 * @SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE: Unload of the Secure Subsystem failed.
 * @SMW_STATUS_SUBSYSTEM_FAILURE: Secure Subsystem operation general failure.
 * @SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED: Secure Subsystem is not configured in the
 * user configuration.
 * @SMW_STATUS_OPERATION_NOT_SUPPORTED: Operation is not supported by the Secure Subsystem.
 * @SMW_STATUS_OPERATION_NOT_CONFIGURED: Operation is not configured in the user configuration.
 * @SMW_STATUS_OPERATION_FAILURE: Operation general failure. Error returned before calling the
 * Secure Subsystem.
 * @SMW_STATUS_NO_KEY_BUFFER: No Key buffer is set in the Key descriptor structure.
 * @SMW_STATUS_OUTPUT_TOO_SHORT: Output buffer is too small. Output size field is updated with
 * the expected size.
 * @SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY: Subsystem memory allocation failure.
 * @SMW_STATUS_SUBSYSTEM_STORAGE_NO_SPACE: Not enough space in the secure subsystem to handle
 * the requested operation.
 * @SMW_STATUS_SUBSYSTEM_STORAGE_ERROR: Generic secure subsystem storage error.
 * @SMW_STATUS_SUBSYSTEM_CORRUPT_OBJECT: An object stored in the secure subsystem is corrupted.
 * @SMW_STATUS_SUBSYSTEM_LOADED: Secure Subsystem is loaded
 * @SMW_STATUS_SUBSYSTEM_NOT_LOADED: Secure Subsystem is not loaded
 *
 * @SMW_STATUS_OPS_INVALID: OSAL operations structure is invalid.
 * @SMW_STATUS_MUTEX_INIT_FAILURE: Mutex initalization has failed.
 * @SMW_STATUS_MUTEX_DESTROY_FAILURE: Mutex destruction has failed.
 * @SMW_STATUS_LIBRARY_ALREADY_INIT: Library already initialized
 *
 * @SMW_STATUS_INVALID_VERSION: The version of the configuration file is not supported.
 * @SMW_STATUS_INVALID_BUFFER: The configuration file passed by OSAL to the library is not valid.
 * @SMW_STATUS_EOF: The configuration file is syntactically too short.
 * @SMW_STATUS_SYNTAX_ERROR: The configuration file is syntactically wrong.
 * @SMW_STATUS_TOO_LARGE_NUMBER: The configuration file defines a too big numeral value.
 * @SMW_STATUS_INVALID_TAG: Tag is invalid.
 * @SMW_STATUS_RANGE_DUPLICATE: Size range is defined more than once for a given algorithm.
 * @SMW_STATUS_ALGO_NOT_CONFIGURED: Size range is defined but the corresponding algorithm is not
 * configured.
 * @SMW_STATUS_CONFIG_ALREADY_LOADED: User configuration is already loaded. To load another one,
 * the Unload configuration API must be called first.
 * @SMW_STATUS_NO_CONFIG_LOADED: No user configuration is loaded.
 * @SMW_STATUS_LOAD_METHOD_DUPLICATE: The load/unload method is defined more than once.
 *
 * @SMW_STATUS_SIGNATURE_INVALID: The Signature is not valid.
 * @SMW_STATUS_SIGNATURE_LEN_INVALID: The Signature length is not valid.
 *
 * Status code classification:
 ** Common return codes
 *
 *	- SMW_STATUS_OK
 *	- SMW_STATUS_UNKNOWN_NAME
 *	- SMW_STATUS_UNKNOWN_ID
 *	- SMW_STATUS_ALLOC_FAILURE
 *	- SMW_STATUS_INVALID_PARAM
 *	- SMW_STATUS_VERSION_NOT_SUPPORTED
 *	- SMW_STATUS_SUBSYSTEM_LOAD_FAILURE
 *	- SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE
 *	- SMW_STATUS_SUBSYSTEM_FAILURE
 *	- SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED
 *	- SMW_STATUS_OPERATION_NOT_SUPPORTED
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED
 *	- SMW_STATUS_OPERATION_FAILURE
 *	- SMW_STATUS_NO_KEY_BUFFER
 *	- SMW_STATUS_OUTPUT_TOO_SHORT
 *	- SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY
 *	- SMW_STATUS_SUBSYSTEM_STORAGE_NO_SPACE
 *	- SMW_STATUS_SUBSYSTEM_STORAGE_ERROR
 *	- SMW_STATUS_SUBSYSTEM_CORRUPT_OBJECT
 *	- SMW_STATUS_SUBSYSTEM_LOADED
 *	- SMW_STATUS_SUBSYSTEM_NOT_LOADED
 *
 ** Specific return codes - Library initialization
 *
 *	- SMW_STATUS_OPS_INVALID,
 *	- SMW_STATUS_MUTEX_INIT_FAILURE,
 *	- SMW_STATUS_MUTEX_DESTROY_FAILURE
 *	- SMW_STATUS_LIBRARY_ALREADY_INIT
 *
 ** Specific return codes - Configuration file
 *
 *	- SMW_STATUS_INVALID_VERSION
 *	- SMW_STATUS_INVALID_BUFFER
 *	- SMW_STATUS_EOF
 *	- SMW_STATUS_SYNTAX_ERROR
 *	- SMW_STATUS_TOO_LARGE_NUMBER
 *	- SMW_STATUS_INVALID_TAG
 *	- SMW_STATUS_RANGE_DUPLICATE
 *	- SMW_STATUS_ALGO_NOT_CONFIGURED
 *	- SMW_STATUS_CONFIG_ALREADY_LOADED
 *	- SMW_STATUS_NO_CONFIG_LOADED
 *	- SMW_STATUS_LOAD_METHOD_DUPLICATE
 *
 ** Specific return codes - Signature
 *
 *	- SMW_STATUS_SIGNATURE_INVALID
 *	- SMW_STATUS_SIGNATURE_LEN_INVALID
 *
 */

/* Status codes */
enum smw_status_code {
	SMW_STATUS_OK = 0,
	SMW_STATUS_INVALID_VERSION,
	SMW_STATUS_INVALID_BUFFER,
	SMW_STATUS_EOF,
	SMW_STATUS_SYNTAX_ERROR,
	SMW_STATUS_UNKNOWN_NAME, /* 5 */
	SMW_STATUS_UNKNOWN_ID,
	SMW_STATUS_TOO_LARGE_NUMBER,
	SMW_STATUS_ALLOC_FAILURE,
	SMW_STATUS_INVALID_PARAM,
	SMW_STATUS_VERSION_NOT_SUPPORTED, /* 10 */
	SMW_STATUS_SUBSYSTEM_LOAD_FAILURE,
	SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE,
	SMW_STATUS_SUBSYSTEM_FAILURE,
	SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED,
	SMW_STATUS_OPERATION_NOT_SUPPORTED, /* 15 */
	SMW_STATUS_OPERATION_NOT_CONFIGURED,
	SMW_STATUS_OPERATION_FAILURE,
	SMW_STATUS_SIGNATURE_INVALID,
	SMW_STATUS_NO_KEY_BUFFER,
	SMW_STATUS_OUTPUT_TOO_SHORT, /* 20 */
	SMW_STATUS_SIGNATURE_LEN_INVALID,
	SMW_STATUS_OPS_INVALID,
	SMW_STATUS_MUTEX_INIT_FAILURE,
	SMW_STATUS_MUTEX_DESTROY_FAILURE,
	SMW_STATUS_INVALID_TAG, /* 25 */
	SMW_STATUS_RANGE_DUPLICATE,
	SMW_STATUS_ALGO_NOT_CONFIGURED,
	SMW_STATUS_CONFIG_ALREADY_LOADED,
	SMW_STATUS_NO_CONFIG_LOADED,
	SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY, /* 30 */
	SMW_STATUS_SUBSYSTEM_STORAGE_NO_SPACE,
	SMW_STATUS_SUBSYSTEM_STORAGE_ERROR,
	SMW_STATUS_SUBSYSTEM_CORRUPT_OBJECT,
	SMW_STATUS_LOAD_METHOD_DUPLICATE,
	SMW_STATUS_LIBRARY_ALREADY_INIT, /* 35 */
	SMW_STATUS_SUBSYSTEM_LOADED,
	SMW_STATUS_SUBSYSTEM_NOT_LOADED
};

#endif /* __SMW_STATUS_H__ */
