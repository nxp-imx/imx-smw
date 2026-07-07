/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#define PSA_COMPLIANT

#include "constants.h"
#include "list.h"

#include "keymgr.h"

/**
 * struct hdl - ELE handles
 * @session: Session handle
 * @key_store: Key store service flow handle
 * @create_key_store: Request the key storage creation
 * @key_store_mutex: Mutex of the key store
 *
 * This structure stores the ELE handles managed by the SMW library.
 */
struct hdl {
	uint32_t session;
	uint32_t storage_id;
	uint32_t key_store;
	bool create_key_store;
	void *key_store_mutex;
	void *mu_base;
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
 * @sign_verif_opaque_key: True if the signature verification support opaque key
 * @edwards_be: True if the Edwards key and signature are big endian in ELE
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
	bool sign_verif_opaque_key;
	bool edwards_be;
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
 * @ele_ctx: Pointer to the ELE subsystem context structure.
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
bool ele_sign_verify_handle(struct subsystem_context *ele_ctx,
			    enum operation_id operation_id, void *args,
			    int *status);

/**
 * ele_rng_init() - Initialize the ELE RNG
 * @hdl: Pointer to the ELE handles structure.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 */
int ele_rng_init(struct hdl *hdl);

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
 * ele_asymmetric_encryption_handle() - Handle the asymmetric encryption and
 *                                      decryption operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the asymmetric encryption and decryption operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_asymmetric_encryption_handle(struct subsystem_context *ele_ctx,
				      enum operation_id operation_id,
				      void *args, int *status);

/**
 * ele_convert_err() - Convert ELE error into SMW status.
 * @err: ELE error code.
 *
 * Return:
 * SMW status
 */
int ele_convert_err(uint32_t err);

/**
 * ele_get_ctx_ops() - Return ELE context operations structure
 *
 * Return:
 * Pointer to ELE context operations structure
 */
void *ele_get_ctx_ops(void);

#endif /* __COMMON_H__ */
