/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <hsm_api.h>

#include "keymgr_derive.h"

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
 * hsm_key_handle() - Handle the Key operations.
 * @hdl: Pointer to the HSM handles structure.
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
bool hsm_key_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status);

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
 * derive_key() - HSM key derivation operation.
 * @hdl: Pointer to the HSM handles structure.
 * @args: Pointer to the derive key arguments.
 *
 * Return:
 * SMW status
 */
int derive_key(struct hdl *hdl, struct smw_keymgr_derive_key_args *args);

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

#endif /* __COMMON_H__ */
