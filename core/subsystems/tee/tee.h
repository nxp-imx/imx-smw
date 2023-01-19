/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023 NXP
 */

#ifndef TEE_H
#define TEE_H

#include "keymgr.h"

#include "tee_subsystem.h"

/*
 * Set the type @p of the parameter @i in the operation parameter
 * type @t.
 */
#define SET_TEEC_PARAMS_TYPE(t, p, i)                                          \
	do {                                                                   \
		__typeof__(t) *_t = &(t);                                      \
		__typeof__(p) _p = (p);                                        \
		__typeof__(i) _i = (i);                                        \
		*_t = SET_CLEAR_MASK(*_t, (_p & 0xF) << (_i * 4),              \
				     (0xF << (_i * 4)));                       \
	} while (0)

#ifndef TEEC_ERROR_SIGNATURE_INVALID
#define TEEC_ERROR_SIGNATURE_INVALID 0xFFFF3072
#endif

/**
 * tee_convert_key_type() - Convert SMW key type to TEE key type.
 * @smw_key_type: SMW key type.
 * @tee_key_type: TEE key type. Not updated if conversion can't be done.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Invalid key type.
 */
int tee_convert_key_type(enum smw_config_key_type_id smw_key_type,
			 enum tee_key_type *tee_key_type);

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
int execute_tee_cmd(uint32_t cmd_id, TEEC_Operation *op);

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
 * tee_get_ctx_ops() - Return TEE context operations structure
 *
 * Return:
 * Pointer to TEE context operations structure
 */
struct smw_crypto_context_ops *tee_get_ctx_ops(void);

/**
 * convert_tee_result() - Convert TEE result into SMW status.
 * @result: TEE result.
 *
 * Return:
 * SMW status.
 */
int convert_tee_result(TEEC_Result result);

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

#endif /* TEE_H */
