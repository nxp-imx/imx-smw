/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
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
 * get_hash_algo() - Get the ELE hash algorithm information
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
 * This function handles the signarture generation and verification operation.
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
 * This function handles the cipher encryption/decrytion operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_cipher_handle(struct hdl *hdl, enum operation_id operation_id,
		       void *args, int *status);

/**
 * ele_device_info_handle() - Handle the device information management operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the device information management operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_device_info_handle(struct subsystem_context *ele_ctx,
			    enum operation_id operation_id, void *args,
			    int *status);

/**
 * ele_device_attest_handle() - Handle the device attestation management operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the device attestation management operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_device_attest_handle(struct subsystem_context *ele_ctx,
			      enum operation_id operation_id, void *args,
			      int *status);

/**
 * ele_device_lifecycle_handle() - Handle the device lifecycle operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the device lifecycle management operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_device_lifecycle_handle(struct subsystem_context *ele_ctx,
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
 * @key_type_id: SMW Key type id
 * @ele_type: ELE key type corresponding
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Key type not supported
 */
int ele_set_pubkey_type(enum smw_config_key_type_id key_type_id,
			hsm_pubkey_type_t *ele_type);

/**
 * ele_set_key_policy() - Convert the user key policy to ELE key policy
 * @policy: Pointer to the key policy
 * @policy_len: Length of @policy
 * @ele_usage: ELE key usage(s) bit mask
 * @ele_algo: ELE key permitted algorithm (first algorithm defined)
 * @actual_policy: Key attributes policy used
 * @actual_policy_len: Length of key attributes policy used
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_KEY_POLICY_ERROR           - User key policy definition error
 * SMW_STATUS_KEY_POLICY_WARNING_IGNORED - One of the user key policy is ignored
 * Other SMW status error.
 */
int ele_set_key_policy(const unsigned char *policy, unsigned int policy_len,
		       hsm_key_usage_t *ele_usage,
		       hsm_permitted_algo_t *ele_algo,
		       unsigned char **actual_policy,
		       unsigned int *actual_policy_len);

/**
 * ele_get_key_policy() - Convert the ELE key policy to user key policy
 * @policy: Pointer to the key policy
 * @policy_len: Length of @policy
 * @ele_usage: ELE key usage(s) bit mask
 * @ele_algo: ELE key permitted algorithm
 *
 * On success, the function allocates the @policy buffer and returns its length
 * in the @policy_len.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_INVALID_PARAM              - Invalid parameters
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failure
 * SMW_STATUS_OPERATION_FAILURE          - Unexpected operation failure
 */
int ele_get_key_policy(unsigned char **policy, unsigned int *policy_len,
		       hsm_key_usage_t ele_usage,
		       hsm_permitted_algo_t ele_algo);

/**
 * ele_export_public_key() - Export the ELE public key
 * @hdl: Pointer to the ELE handles structure.
 * @key_desc: Key descriptor
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
 * @lifecycle: SMW Device lifecycle
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
 * ele_get_key_lifecycle() - Convert the ELE lifecycle to user lifecycle
 * @lifecycle: Pointer to the lifecycle string
 * @lifecycle_len: Length of @lifecycle
 * @ele_lifecycle: ELE lifecycle(s) bit mask
 *
 * On success, the function allocates the @lifecycle buffer and returns its
 * length in the @lifecycle_len.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_INVALID_PARAM              - Invalid parameters
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failure
 * SMW_STATUS_OPERATION_FAILURE          - Unexpected operation failure
 */
int ele_get_key_lifecycle(unsigned char **lifecycle,
			  unsigned int *lifecycle_len,
			  hsm_key_lifecycle_t ele_lifecycle);

/**
 * ele_set_lifecycle_flags() - Convert the SMW lifecycle flags to ELE flags
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @smw_flags: SMW lifecycle flags
 * @ele_flags: ELE lifecycle flags
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
			    unsigned long smw_flags, uint16_t *ele_flags);

/**
 * ele_set_cipher_algo() - Set the ELE cipher algorithm
 * @key_type_id: SMW Key type id
 * @cipher_mode_id: SMW cipher mode ID
 * @cipher_algo: ELE cipher algorithm ID
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

#endif /* __COMMON_H__ */
