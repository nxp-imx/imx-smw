/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef __SMW_OSAL_H__
#define __SMW_OSAL_H__

#include <stddef.h>

#include "smw_status.h"
#include "smw_strings.h"

/**
 * DOC:
 * The OSAL interface is the library API specific to the Operating System.
 * It's under the charge of the library integrator to adapt the OSAL library
 * part to the OS targeted.
 */

/**
 * smw_osal_latest_subsystem_name() - Return the latest Secure Subsystem name
 *
 * In DEBUG mode only, function returns the name of the latest Secure Subsystem
 * invoked by SMW.
 * This Secure Subsystem have been either explicitly requested by the caller or
 * selected by SMW given the operation arguments and the configuration file.
 * In other modes, function always returns NULL.
 *
 * Return:
 * In DEBUG mode only, the pointer to the static buffer containing the
 * null-terminated string name of the Secure Subsystem.
 * In other modes, NULL
 */
const char *smw_osal_latest_subsystem_name(void);

/**
 * smw_osal_lib_init() - Initialize the SMW library
 *
 * This function must be the first function called by the application opening
 * a library instance.
 * It loads the subsystem configuration set in the linux environment
 * variable SMW_CONFIG_FILE.
 *
 * Return:
 * SMW_STATUS_OK                   - Library initialization success
 * SMW_STATUS_LIBRARY_ALREADY_INIT - Library already initialized
 * otherwise any of the smw status
 */
enum smw_status_code smw_osal_lib_init(void);

/* Size of the TEE TA UUID string size including the null terminator */
#define TEE_TA_UUID_SIZE_MAX 37

/**
 * struct tee_info - TEE Subsystem information
 * @ta_uuid: TA UUID
 */
struct tee_info {
	char ta_uuid[TEE_TA_UUID_SIZE_MAX];
};

/**
 * struct se_info - Secure Enclave information
 * @storage_id: Key storage identifier
 * @storage_nonce: Key storage nonce
 * @storage_replay: Replay attack counter
 */
struct se_info {
	unsigned int storage_id;
	unsigned int storage_nonce;
	unsigned short storage_replay;
};

/**
 * smw_osal_set_subsystem_info() - Set the Subsystem configuration information
 * @subsystem: Subsystem name
 * @info: Subsystem information
 * @info_size: Size in bytes of @info parameter
 *
 * This function must be called before a subsystem is loaded.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_SUBSYSTEM_LOADED  - Subsystem is already loaded
 * SMW_STATUS_INVALID_PARAM     - Function parameter error
 * SMW_STATUS_ALLOC_FAILURE     - Allocation failure
 * SMW_STATUS_UNKNOWN_NAME      - Subsystem unknown
 */
enum smw_status_code smw_osal_set_subsystem_info(smw_subsystem_t subsystem,
						 void *info, size_t info_size);

/**
 * smw_osal_open_key_db() - Open a key database file
 * @file: Fullname of the key database
 * @len: Length of the @file string
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_KEY_DB_INIT       - Initialization error of the database
 */
enum smw_status_code smw_osal_open_key_db(const char *file, size_t len);
#endif /* __SMW_OSAL_H__ */
