/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2025 NXP
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#define PSA_COMPLIANT
#include <hsm_api.h>

#include "constants.h"
#include "list.h"

#include "keymgr_derive.h"

#define ELE_NB_UID_WORD 4
#define ELE_UID_SIZE	(ELE_NB_UID_WORD * sizeof(uint32_t))

/**
 * struct hash_context - Hash context
 * @ele_algo: ELE Hash algorithm
 * @ele_ctx: ELE operation context
 * @ele_ctx_size: ELE operation context size
 * @digest_length: Digest length
 */
struct hash_context {
	hsm_hash_algo_t ele_algo;
	uint8_t *ele_ctx;
	uint16_t ele_ctx_size;
	uint32_t digest_length;
};

/**
 * struct hdl - ELE handles
 * @session: Session handle
 * @key_store: Key store service flow handle
 *
 * This structure stores the ELE handles managed by the SMW library.
 */
struct hdl {
	hsm_hdl_t session;
	hsm_hdl_t key_store;
};

/**
 * struct ele_info - ELE information
 * @mutex: Mutex of the ELE information access
 * @valid: True if structure has been initialized
 * @attest_api_ver: Attestation API version
 * @soc_rev: SoC Revision
 * @soc_id: SoC ID
 * @lifecycle: Current device lifecycle
 * @uid_length: Chip Unique ID length
 * @uid: Chip Unique ID buffer
 * @srkh_fused: True if OEM SRKH is fused
 *
 * This structure stores some useful ELE information.
 */
struct ele_info {
	void *mutex;
	bool valid;
	uint8_t attest_api_ver;
	uint16_t soc_rev;
	uint16_t soc_id;
	uint16_t lifecycle;
	unsigned int uid_length;
	unsigned char *uid;
	bool srkh_fused;
};

/**
 * struct subsystem_context - ELE subsystem context
 * @hdl: ELE handles
 * @key_grp_list: Key group list
 * @key_grp_mutex: Mutex of the key group list access
 * @info: ELE information
 */
struct subsystem_context {
	struct hdl hdl;
	struct smw_utils_list key_grp_list;
	void *key_grp_mutex;
	struct ele_info info;
};

struct ele_hash_algo {
	enum smw_config_hash_algo_id algo_id;
	hsm_hash_algo_t ele_algo;
	uint32_t length;
};

/**
 * ele_get_hash_algo() - Get the ELE hash algorithm information
 * @algo_id: SMW Hash algorithm id.
 *
 * Return:
 * NULL if algorithm not found, otherwise reference to the hash algorithm
 * information.
 */
const struct ele_hash_algo *
ele_get_hash_algo(enum smw_config_hash_algo_id algo_id);

/**
 * ele_key_handle() - Handle the Key operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the Key operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_key_handle(struct subsystem_context *ele_ctx,
		    enum operation_id operation_id, void *args, int *status);

/**
 * ele_hash_handle() - Handle the Hash operation.
 * @hdl: Pointer to the ELE handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the Hash operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_hash_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status);

/**
 * ele_mac_handle() - Handle the MAC operation.
 * @hdl: Pointer to the ELE handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the MAC operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_mac_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status);

/**
 * ele_sign_verify_handle() - Handle the Sign and Verify operation.
 * @hdl: Pointer to the ELE handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the signature generation and verification operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_sign_verify_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status);

/**
 * ele_rng_handle() - Handle the random generation operation.
 * @hdl: Pointer to the ELE handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the random number generation operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_rng_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status);

/**
 * ele_cipher_handle() - Handle the cipher encryption/decryption operation.
 * @hdl: Pointer to the ELE handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the cipher encryption/decryption operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_cipher_handle(struct hdl *hdl, enum operation_id operation_id,
		       void *args, int *status);

/**
 * ele_device_manager_handle() - Handle the device management operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the device management operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_device_manager_handle(struct subsystem_context *ele_ctx,
			       enum operation_id operation_id, void *args,
			       int *status);

/**
 * ele_storage_handle() - Handle the storage operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the storage operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_storage_handle(struct subsystem_context *ele_ctx,
			enum operation_id operation_id, void *args,
			int *status);

/**
 * ele_aead_handle() - Handle the AEAD encryption/decryption operation.
 * @hdl: Pointer to the ELE handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the AEAD encryption/decryption operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_aead_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status);

/**
 * ele_derive_key() - ELE key derivation operation.
 * @hdl: Pointer to the ELE handles structure.
 * @args: Pointer to the derive key arguments.
 *
 * Return:
 * SMW status
 */
int ele_derive_key(struct hdl *hdl, struct smw_keymgr_derive_key_args *args);

/**
 * ele_convert_err() - Convert ELE error into SMW status.
 * @err: ELE error code.
 *
 * Return:
 * SMW status
 */
int ele_convert_err(hsm_err_t err);

/**
 * ele_set_pubkey_type() - Set the ELE public key type
 * @key_type_id: SMW Key type ID.
 * @ele_type: ELE key type corresponding.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Key type not supported
 */
int ele_set_pubkey_type(enum smw_config_key_type_id key_type_id,
			hsm_pubkey_type_t *ele_type);

/**
 * ele_set_key_policy() - Convert the user key policy to ELE key policy
 * @ele_permitted_algo: Pointer to ELE permitted algorithm.
 * @ele_usage_flags: Pointer to ELE usage flags.
 * @smw_permitted_algo: SMW permitted algorithm.
 * @smw_usage_flags: SMW usage flags.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_KEY_POLICY_WARNING_IGNORED - One of the user key policy is ignored
 * Other SMW status error.
 */
void ele_set_key_policy(hsm_permitted_algo_t *ele_permitted_algo,
			hsm_key_usage_t *ele_usage_flags,
			smw_attr_algo_t smw_permitted_algo,
			smw_attr_usage_t smw_usage_flags);

/**
 * ele_get_key_policy() - Convert the ELE key policy to user key policy
 * @smw_permitted_algo: Pointer to SMW permitted algorithm.
 * @smw_usage_flags: Pointer to SMW usage flags.
 * @ele_permitted_algo: ELE permitted algorithm.
 * @ele_usage_flags: ELE usage flags.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_INVALID_PARAM              - Invalid parameters
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failure
 * SMW_STATUS_OPERATION_FAILURE          - Unexpected operation failure
 */
void ele_get_key_policy(smw_attr_algo_t *smw_permitted_algo,
			smw_attr_usage_t *smw_usage_flags,
			hsm_permitted_algo_t ele_permitted_algo,
			hsm_key_usage_t ele_usage_flags);

/**
 * ele_export_public_key() - Export the ELE public key
 * @hdl: Pointer to the ELE handles structure.
 * @key_desc: Key descriptor.
 *
 * The function exports the public key of the given @key_desc->identifier.id.
 * The following fields of @key_desc parameters are output:
 *  - identifier.type_id
 *  - identifier.security_size
 *  - format_id
 *  - pub (if operation success)
 *  - ops (if operation success)
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Key type not supported
 * Other SMW status error.
 */
int ele_export_public_key(struct hdl *hdl,
			  struct smw_keymgr_descriptor *key_desc);

/**
 * ele_get_current_lifecycle_id() - Get the device lifecycle SMW id
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @lifecycle: SMW Device lifecycle.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failure
 * SMW_STATUS_SUBSYSTEM_FAILURE          - Subsystem failure
 * SMW_STATUS_OPERATION_NOT_SUPPORTED    - Operation not supported
 * SMW_STATUS_MUTEX_LOCK_FAILURE         - Mutex lock failure
 * SMW_STATUS_MUTEX_UNLOCK_FAILURE       - Mutex unlock failure
 * Other SMW status error.
 */
int ele_get_device_lifecycle_id(struct subsystem_context *ele_ctx,
				unsigned int *lifecycle);

/**
 * ele_get_key_lifecycles() - Convert the ELE lifecycles to SMW lifecycles
 * @ele_lifecycle: ELE lifecycle(s) bit mask.
 * @attributes: SMW key attributes.
 *
 * Return:
 * None.
 */
void ele_get_key_lifecycles(hsm_key_lifecycle_t ele_lifecycles,
			    smw_attr_attributes_t *attributes);

/**
 * ele_set_lifecycle_flags() - Convert the SMW lifecycle flags to ELE flags
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @attributes: SMW key attributes.
 * @ele_flags: ELE lifecycle flags.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_MUTEX_LOCK_FAILURE         - Mutex lock failure
 * SMW_STATUS_MUTEX_UNLOCK_FAILURE       - Mutex unlock failure
 * SMW_STATUS_INVALID_PARAM              - Invalid parameters
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failure
 * SMW_STATUS_OPERATION_FAILURE          - Unexpected operation failure
 */
int ele_set_lifecycle_flags(struct subsystem_context *ele_ctx,
			    smw_attr_attributes_t attributes,
			    uint16_t *ele_flags);

/**
 * ele_set_cipher_algo() - Set the ELE cipher algorithm
 * @key_type_id: SMW Key type ID.
 * @cipher_mode_id: SMW cipher mode ID.
 * @cipher_algo: ELE cipher algorithm ID.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Cipher mode not supported
 */
int ele_set_cipher_algo(enum smw_config_key_type_id key_type_id,
			enum smw_config_cipher_mode_id cipher_mode_id,
			hsm_op_cipher_one_go_algo_t *cipher_algo);

/**
 * ele_get_device_info() - Get the device information
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 *
 * This function writes ELE information only once.
 * Thus only the writing of ELE information must be mutex protected.
 * The reading of ELE information does not need to be mutex protected
 * as long as this function is called first.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failure
 * SMW_STATUS_SUBSYSTEM_FAILURE          - Subsystem failure
 * SMW_STATUS_OPERATION_NOT_SUPPORTED    - Operation not supported
 * SMW_STATUS_MUTEX_LOCK_FAILURE         - Mutex lock failure
 * SMW_STATUS_MUTEX_UNLOCK_FAILURE       - Mutex unlock failure
 * Other SMW status error.
 */
int ele_get_device_info(struct subsystem_context *ele_ctx);

/**
 * ele_is_oem_srkh_fused() - Return if the OEM SRKH is fused
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @fused: True if the OEM SRKH is fused.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failure
 * SMW_STATUS_SUBSYSTEM_FAILURE          - Subsystem failure
 * SMW_STATUS_OPERATION_NOT_SUPPORTED    - Operation not supported
 * SMW_STATUS_MUTEX_LOCK_FAILURE         - Mutex lock failure
 * SMW_STATUS_MUTEX_UNLOCK_FAILURE       - Mutex unlock failure
 * Other SMW status error.
 */
int ele_is_oem_srkh_fused(struct subsystem_context *ele_ctx, bool *fused);

/**
 * ele_get_ctx_ops() - Return ELE context operations structure
 *
 * Return:
 * Pointer to ELE context operations structure
 */
void *ele_get_ctx_ops(void);

/**
 * open_key_mgmt_service() - Open a key management service flow
 * @hdl: Pointer to subsystem context handlers
 * @key_management_hdl: Return the key manager service handler
 *
 * Return:
 * SMW_STATUS_OK                   - Success
 * SMW_STATUS_SUBSYSTEM_FAILURE    - Subsystem failure
 */
int open_key_mgmt_service(struct hdl *hdl, hsm_hdl_t *key_management_hdl);

/**
 * close_key_mgt_service() - Close the key management service flow
 * @key_management_hdl: Key manager service handler to close
 *
 * Return:
 * SMW_STATUS_OK                   - Success
 * SMW_STATUS_SUBSYSTEM_FAILURE    - Subsystem failure
 */
int close_key_mgt_service(hsm_hdl_t key_management_hdl);

/**
 * ele_free_hash_context() - Free the ELE Hash context
 * @ctx: Hash context
 *
 * Return:
 * None.
 */
void ele_free_hash_context(struct hash_context *ctx);

/**
 * ele_get_key_store_id() - Get the configured ELE keystore identifier
 * @keystore_id: The ELE keystore identifier
 *
 * Return:
 * SMW_STATUS_OK                   - Success
 * SMW_STATUS_INVALID_PARAM        - Cannot retrieve ELE configuration
 */
int ele_get_key_store_id(uint32_t *keystore_id);

/**
 * ele_get_key_type() - Get ELE key type from SMW key type
 * @key_type_id: The SMW key type identifier
 * @ele_key_type: The ELE key type
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Cannot retrieve ELE key type
 */
int ele_get_key_type(enum smw_config_key_type_id key_type_id,
		     hsm_key_type_t *ele_key_type);

#endif /* __COMMON_H__ */
