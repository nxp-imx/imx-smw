/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2026 NXP
 */

#ifndef __SMW_OSAL_H__
#define __SMW_OSAL_H__

#include <stdbool.h>
#include <stddef.h>

#include "smw_status.h"
#include "smw/names.h"

/**
 * TEE_TA_UUID_SIZE_MAX - Size in bytes of the TEE TA UUID.
 *
 * Size in bytes of the TEE TA UUID string size including the null terminator.
 */
#define TEE_TA_UUID_SIZE_MAX 37

/**
 * struct tee_info - TEE Subsystem information
 * @ta_uuid: TEE TA UUID value as a null-terminated string.
 */
struct tee_info {
	char ta_uuid[TEE_TA_UUID_SIZE_MAX];
};

/**
 * struct se_info - Secure Enclave information about the NVM Secure Storage
 * @storage_id: User defined identifier.
 * @storage_nonce: User defined nonce to authentify the storage.
 * @storage_replay: Replay attack counter (Only for SECO Secure Subsystem).
 * @storage_shared: Allows to share storage between multiple applications
 *                  (Only for ELE Secure Subsystem).
 */
struct se_info {
	unsigned int storage_id;
	unsigned int storage_nonce;
	unsigned short storage_replay;
	bool storage_shared;
};

/**
 * smw_osal_latest_subsystem_name() - Return the latest Secure Subsystem name.
 *
 * In DEBUG mode only, function returns the name of the latest Secure Subsystem
 * invoked by SMW.
 * This Secure Subsystem have been either explicitly requested by the caller or
 * selected by SMW given the operation arguments and the configuration file.
 * In other modes, function always returns NULL.
 *
 * Return:
 *  - The latest active Secure Subsystem name, in DEBUG mode only,
 *  - SMW_SUBSYSTEM_NAME_NONE otherwise.
 */
smw_subsystem_t smw_osal_latest_subsystem_name(void);

/**
 * smw_osal_lib_init() - Initialize the SMW library
 *
 * This function must be called before any key management, cryptographic
 * operations to initialize the SMW library.
 *
 * It loads the subsystem configuration either defined in the system `smw.conf`
 * file or by set in the linux environment variable SMW_CONFIG_FILE.
 *
 * .. caution::
 *   The environment variable takes precedence over the configuration file.
 *
 * .. note::
 *	This function is not thread-safe. Other initialization functions
 *	from the PSA or PKCS#11 APIs can call this function directly or
 *	indirectly. When using those APIs, prefer using only those methods of
 *	initialization, e.g. psa_crypto_init() or C_Initialize() respectively.
 *	This function should only be called when using the SMW APIs.
 *
 * Return:
 *  - SMW_STATUS_OK
 *      Library initialization success.
 *  - SMW_STATUS_LIBRARY_ALREADY_INIT
 *      Library already initialized.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_osal_lib_init(void);

/**
 * smw_osal_set_subsystem_info() - Set the Subsystem configuration information.
 * @subsystem: [in] Subsystem name.
 * @info: [in] Subsystem information.
 * @info_size: [in] Size in bytes of @info parameter.
 *
 * This function sets the subsystem configuration information used when
 * the subsystem is loaded.
 *
 * .. caution::
 *   This method overwrites the configuration set in file `smw.conf`.
 *
 * Return:
 *  - SMW_STATUS_OK
 *      Success.
 *  - SMW_STATUS_SUBSYSTEM_LOADED
 *      Subsystem is already loaded.
 *  - SMW_STATUS_INVALID_PARAM
 *      Function parameter error.
 *  - SMW_STATUS_ALLOC_FAILURE
 *      Allocation failure.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME
 *      Unknown subsystem name.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_osal_set_subsystem_info(smw_subsystem_t subsystem,
						 void *info, size_t info_size);

/**
 * smw_osal_open_obj_db() - Setup the object database file to open.
 * @file: [in] Fullname of the object database, null-terminated string.
 * @len: [in] Length is bytes of the filename string.
 *
 * If the library is already initialized, database may be already in use by
 * another application. If application must be separated, this function
 * allows to define database file per application overwritten the file
 * set in the system configuration file 'smw.conf'.
 * This function must be called before smw_osal_lib_init().
 *
 * .. caution::
 *   This method overwrites the configuration set in file `smw.conf`.
 *
 * Return:
 *  - SMW_STATUS_OK
 *      Success.
 *  - SMW_STATUS_LIBRARY_ALREADY_INIT
 *      Library already initialized.
 *  - SMW_STATUS_CONFIGURATION_FAILURE
 *      Error of configuration.
 *  - SMW_STATUS_ALLOC_FAILURE
 *      Out of memory.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_osal_open_obj_db(const char *file, size_t len);

#endif /* __SMW_OSAL_H__ */
