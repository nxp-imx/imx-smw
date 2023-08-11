/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <hsm_api.h>

#include "list.h"

#include "keymgr_derive.h"

#define HSM_MAX_KEY_GROUP	       1024U
#define HSM_FIRST_PERSISTENT_KEY_GROUP 0U
#define HSM_FIRST_TRANSIENT_KEY_GROUP  (HSM_MAX_KEY_GROUP / 2)
#define HSM_LAST_PERSISTENT_KEY_GROUP  (HSM_FIRST_TRANSIENT_KEY_GROUP - 1)
#define HSM_LAST_TRANSIENT_KEY_GROUP   (HSM_MAX_KEY_GROUP - 1)

/**
 * struct hdl - HSM handles
 * @session: Session handle
 * @key_store: Key store service flow handle
 * @key_management: Key management service flow handle
 * @signature_gen: Signature generation service flow handle
 * @signature_ver: Signature verification service flow handle
 * @hash: Hash service flow handle
 * @rng: RNG service flow handle
 * @cipher: Cipher service flow handle
 *
 * This structure stores the HSM handles managed by the SMW library.
 */
struct hdl {
	hsm_hdl_t session;
	hsm_hdl_t key_store;
	hsm_hdl_t key_management;
	hsm_hdl_t signature_gen;
	hsm_hdl_t signature_ver;
	hsm_hdl_t hash;
	hsm_hdl_t rng;
	hsm_hdl_t cipher;
};

/**
 * struct subsystem_context - HSM subsystem context
 * @hdl: HSM handles
 * @nvm_status: NVM storage active status
 * @mutex: Mutex of the subsystem context access
 * @key_grp_list: Key group list
 * @key_grp_mutex: Mutex of the key group list access
 */
struct subsystem_context {
	struct hdl hdl;
	uint32_t nvm_status;
	void *mutex;
	unsigned long tid;
	struct smw_utils_list key_grp_list;
	void *key_grp_mutex;
};

/**
 * hsm_key_handle() - Handle the Key operations.
 * @hsm_ctx: Pointer to the HSM subsystem context structure.
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
bool hsm_key_handle(struct subsystem_context *hsm_ctx,
		    enum operation_id operation_id, void *args, int *status);

/**
 * hsm_hash_handle() - Handle the Hash operation.
 * @hdl: Pointer to the HSM handles structure.
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
bool hsm_hash_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status);

/**
 * hsm_sign_verify_handle() - Handle the Sign and Verify operations.
 * @hdl: Pointer to the HSM handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the Sign and Verify operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool hsm_sign_verify_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status);

/**
 * hsm_derive_key() - HSM key derivation operation.
 * @hsm_ctx: Pointer to the HSM subsystem context structure.
 * @args: Pointer to the derive key arguments.
 *
 * Return:
 * SMW status
 */
int hsm_derive_key(struct subsystem_context *hsm_ctx,
		   struct smw_keymgr_derive_key_args *args);

/**
 * hsm_mac_handle() - Handle the MAC operation.
 * @hdl: Pointer to the HSM handles structure.
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
bool hsm_mac_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status);
/**
 * convert_hsm_err() - Convert HSM error into SMW status.
 * @err: HSM error code.
 *
 * Return:
 * SMW status
 */
int convert_hsm_err(hsm_err_t err);

/**
 * hsm_set_empty_key_policy() - Set empty key policy.
 * @key_attributes: Key attributes.
 *
 * Return:
 * None.
 */
void hsm_set_empty_key_policy(struct smw_keymgr_attributes *key_attributes);

/**
 * hsm_export_public_key() - Export the HSM public key
 * @hdl: Pointer to the HSM handles structure.
 * @key_desc: Key descriptor
 *
 * The function exports the public key of the given @key_desc->identifier.id.
 * The following fields of @key_desc parameters must be set as input:
 *  - identifier.type_id
 *  - identifier.security_size
 *
 * The following fields of @key_desc parameters are output:
 *  - format_id
 *  - pub (if operation success)
 *  - ops (if operation success)
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Key type not supported
 * Other SMW status error.
 */
int hsm_export_public_key(struct hdl *hdl,
			  struct smw_keymgr_descriptor *key_desc);

/**
 * hsm_set_key_group_state() - Set internal key group list state
 * @hsm_ctx: Pointer to HSM subsystem context structure.
 * @grp: Group id.
 * @persistent: True if key group contains persistent keys.
 * @full: True if the key group is full.
 *
 * Find the subsystem key group list the group id, if found, update the
 * status of the key group with the @full status.
 * Else, add a new key group in the list with the type @persistent and the
 * status @full.
 *
 * Return:
 * SMW_STATUS_OK                   - Success
 * SMW_STATUS_MUTEX_LOCK_FAILURE   - Mutex lock failure
 * SMW_STATUS_MUTEX_UNLOCK_FAILURE - Mutex unlock failure
 * SMW_STATUS_OPERATION_FAILURE    - Key group not valid
 * SMW_STATUS_ALLOC_FAILURE        - Out of memory
 */
int hsm_set_key_group_state(struct subsystem_context *hsm_ctx, unsigned int grp,
			    bool persistent, bool full);

/**
 * hsm_get_key_group() - Return a key group id not full
 * @hsm_ctx: Pointer to HSM subsystem context structure.
 * @persistent: True if key is a persistent key.
 * @out_grp: Group id not full.
 *
 * Find the subsystem key group list the group id, if found, update the
 * status of the key group with the @full status.
 * Else, add a new key group in the list with the type @persistent and the
 * status @full.
 *
 * Return:
 * SMW_STATUS_OK                   - Success
 * SMW_STATUS_MUTEX_LOCK_FAILURE   - Mutex lock failure
 * SMW_STATUS_MUTEX_UNLOCK_FAILURE - Mutex unlock failure
 * SMW_STATUS_OPERATION_FAILURE    - No more key group available
 * SMW_STATUS_ALLOC_FAILURE        - Out of memory
 */
int hsm_get_key_group(struct subsystem_context *hsm_ctx, bool persistent,
		      unsigned int *out_grp);

#endif /* __COMMON_H__ */
