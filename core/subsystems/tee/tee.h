/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023-2025 NXP
 */

#ifndef TEE_H
#define TEE_H

#include "keymgr.h"
#include "utils.h"
#include "operation_context.h"
#include "sign_verify.h"

#include "tee_subsystem.h"

#define TEE_MAX_IV_LEN 16

/**
 * struct aead_context - AEAD context
 * @iv: IV buffer
 * @iv_len: @iv length in bytes
 * @tee_handle: TEE operation handle
 */
struct aead_context {
	unsigned char iv[TEE_MAX_IV_LEN];
	unsigned int iv_len;
	void *tee_handle;
};

/**
 * struct cipher_context - Cipher context
 * @tee_handle: TEE operation handle
 */
struct cipher_context {
	void *tee_handle;
};

/**
 * struct hash_context - Hash context
 * @tee_handle: TEE operation handle
 */
struct hash_context {
	void *tee_handle;
};

/**
 * struct sign_context - Signature context
 * @hash_ctx: Hash context
 * @attributes: Signature attributes
 * @eddsa_params: Edwards signature parameters
 * @key_descriptor: Signature key descriptor
 */
struct sign_context {
	struct smw_op_context hash_ctx;
	struct smw_sign_verify_attributes attributes;
	struct smw_eddsa_params eddsa_params;
	struct smw_keymgr_descriptor key_descriptor;
};

/*
 * Set the type @p of the parameter @i in the operation parameter
 * type @t.
 */
#define SET_TEEC_PARAMS_TYPE(t, p, i)                                          \
	do {                                                                   \
		uint32_t _t = (t);                                             \
		uint32_t _p = (p);                                             \
		uint32_t _i = (i);                                             \
		(t) = SET_CLEAR_MASK(_t, (_p & 0xF) << (_i * 4),               \
				     ((uint32_t)0xF << (_i * 4)));             \
	} while (0)

/**
 * tee_convert_key_type() - Convert SMW key type to TEE key type.
 * @key_identifier: Pointer to the key identifier.
 * @hash_algo_id: SMW hash algorithm ID.
 * @key_type: TEE key type. Not updated if conversion can't be done.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Invalid key type.
 */
int tee_convert_key_type(struct smw_keymgr_identifier *key_identifier,
			 enum smw_config_hash_algo_id hash_algo_id,
			 enum tee_key_type *key_type);

/**
 * key_type_tee_to_smw() - Convert TEE key type to SMW key type.
 * @key_type: TEE key type.
 *
 * Return:
 * SMW key type
 */
enum smw_config_key_type_id key_type_tee_to_smw(enum tee_key_type key_type);

/**
 * tee_convert_hash_algorithm_id() - Convert SMW algorithm to TEE algorithm.
 * @smw_id: Hash algorithm ID as defined in SMW.
 * @tee_id: Hash algorithm ID as defined in TEE subsystem.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Invalid key type.
 */
int tee_convert_hash_algorithm_id(enum smw_config_hash_algo_id smw_id,
				  enum tee_algorithm_id *tee_id);

/**
 * execute_tee_cmd() - Invoke a command within the SMW TA session.
 * @cmd_id: ID of the command to execute.
 * @op: Pointer to the operation structure.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_SUBSYSTEM_FAILURE - Operation failed.
 */
int execute_tee_cmd(enum ta_commands cmd_id, TEEC_Operation *op);

/**
 * tee_key_handle() - Handle the key operations.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_key_handle(enum operation_id operation_id, void *args, int *status);

/**
 * tee_hash_handle() - Handle the hash operations.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_hash_handle(enum operation_id operation_id, void *args, int *status);

/**
 * tee_sign_verify_handle() - Handle the sign and verify operations.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_sign_verify_handle(enum operation_id operation_id, void *args,
			    int *status);

/**
 * tee_free_sign_context() - Free the signature context
 * @ctx: Signature context
 *
 * Return:
 * None.
 */
void tee_free_sign_context(struct smw_op_context *ctx);

/**
 * tee_copy_sign_context() - Copy the signature context
 * @src_context: Pointer to source operation context arguments structure
 * @dst_context: Pointer to destination operation context arguments structure
 * @tee_dst_ctx: Pointer to optee context operation handle structure
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_INVALID_PARAM           - Parameter invalid
 * SMW_STATUS_ALLOC_FAILURE           - Memory allocation failure
 */
int tee_copy_sign_context(struct smw_op_context *src_context,
			  struct smw_op_context *dst_context,
			  struct shared_context *tee_dst_ctx);

/**
 * tee_mac_handle() - Handle the MAC operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_mac_handle(enum operation_id operation_id, void *args, int *status);

/**
 * tee_cipher_handle() - Handle the Cipher operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_cipher_handle(enum operation_id operation_id, void *args, int *status);

/**
 * tee_aead_handle() - Handle the AEAD operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_aead_handle(enum operation_id operation_id, void *args, int *status);

/**
 * tee_storage_handle() - Handle the storage operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_storage_handle(enum operation_id operation_id, void *args,
			int *status);

/**
 * tee_asymm_encrypt_decrypt_handle() - Handle asymmetric encryption and
 *                                      decryption operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_asymm_encrypt_decrypt_handle(enum operation_id operation_id,
				      void *args, int *status);

/**
 * tee_get_ctx_ops() - Return TEE context operations structure
 *
 * Return:
 * Pointer to TEE context operations structure
 */
void *tee_get_ctx_ops(void);

/**
 * tee_convert_result() - Convert TEE result into SMW status.
 * @result: TEE result.
 *
 * Return:
 * SMW status.
 */
int tee_convert_result(TEEC_Result result);

/**
 * get_tee_context_ptr() - Get TEE context address.
 *
 * Return:
 * TEE context address
 */
TEEC_Context *get_tee_context_ptr(void);

/**
 * copy_keys_to_shm() - Copy keys in CA/TA shared memory.
 * @shm: Pointer to TEEC shared memory structure.
 * @key_descriptor: Pointer to key descriptor.
 * @privacy: Key privacy.
 *
 * The @shm buffer is allocated, set as input and must be freed using
 * TEEC_ReleaseSharedMemory().
 * This buffer is set as follow:
 * - For Keypair: Public || Private || Modulus
 * - For Public key: Public || Modulus
 * - For Private key: Private || Modulus
 * where || stands for concatenation. Modulus buffer is only for RSA key type.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_INVALID_PARAM		- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY	- Subsystem memory allocation failed.
 */
int copy_keys_to_shm(TEEC_SharedMemory *shm,
		     struct smw_keymgr_descriptor *key_descriptor,
		     enum smw_keymgr_privacy_id privacy);

/**
 * tee_delete_key() - Delete a key in TEE subsystem storage.
 * @id: Key id to delete.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
int tee_delete_key(uint32_t id);

/**
 * tee_import_key_buffer() - Import a key buffer.
 * @key: Internal key descriptor structure
 * @id: Key id to import.
 * @key_usage: Key usage.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
int tee_import_key_buffer(struct smw_keymgr_descriptor *key,
			  unsigned int *key_id, unsigned int key_usage);

/**
 * derive_key() - Derive a key from base key.
 * @args: Derive key arguments structure.
 *
 * A shared secret is derived from a symmetric key and it is stored in
 * the TEE storage.
 *
 * Return:
 * SMW_STATUS_OK                         - Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED    - Operation parameters not supported.
 * SMW_STATUS_INVALID_PARAM              - One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE              - Memory allocation failed.
 * SMW_STATUS_OPERATION_FAILURE          - Operation failed.
 * SMW_STATUS_SUBSYSTEM_FAILURE          - Trusted application failed.
 * SMW_STATUS_KEY_POLICY_WARNING_IGNORED - One of the key policy is ignored.
 * SMW_STATUS_OUTPUT_TOO_SHORT           - Output buffer is too short.
 */
int derive_key(void *args);

/**
 * key_usage_to_tee() - Convert SMW key usage to TEE key usage value.
 * @smw: SMW key usage.
 * @tee: TEE key usage.
 *
 * Return:
 * None
 */
void key_usage_to_tee(smw_attr_usage_t smw, unsigned int *tee);

/**
 * key_usage_to_smw() - Convert TEE key usage to SMW key usage.
 * @tee: TEE key usage.
 * @smw: SMW key usage.
 *
 * Return:
 * None
 */
void key_usage_to_smw(unsigned int tee, smw_attr_usage_t *smw);

/**
 * check_persistence() - Check SMW key persistence.
 * @attributes: SMW key attributes.
 * @persistent_flag: Flag to specify whether to use persistent storage.
 *
 * Return:
 * SMW_STATUS_OK                         - Success.
 * SMW_STATUS_INVALID_PARAM              - One of the parameter is invalid.
 */
int check_persistence(smw_attr_attributes_t attributes, bool *persistent_flag);

/**
 * set_tmpref_buffer() - Set a shared tmpref buffer parameter.
 * @buffer_type: TEEC memory type.
 * @param_idx: Index of the parameter in @op structure.
 * @buffer: Pointer to the buffer.
 * @buffer_len: @buffer length in bytes.
 * @op: Pointer to operation structure to update.
 *
 * Return:
 * SMW_STATUS_OK            - Success.
 * SMW_STATUS_INVALID_PARAM - Invalid index.
 */
int set_tmpref_buffer(unsigned int mem_type, unsigned int param_idx,
		      unsigned char *buffer, unsigned int buffer_len,
		      TEEC_Operation *op);

#endif /* TEE_H */
