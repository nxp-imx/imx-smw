/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
 */

#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "exec.h"
#include "operation_context.h"

/**
 * struct smw_crypto_cipher_args - Internal cipher arguments structure
 * @keys_desc: Pointer to an array of internal key descriptor structure pointer
 * @nb_keys: Number of entries of the array key descriptor pointer
 * @mode_id: Cipher mode ID
 * @op_type_id: Operation type ID
 * @handle: Pointer to operation handle
 * @op_step: Multi-part operation step
 * @init_pub: Pointer to the public cipher init arguments structure
 * @data_pub: Pointer to the public cipher data arguments structure
 */
struct smw_crypto_cipher_args {
	struct smw_keymgr_descriptor **keys_desc;
	unsigned int nb_keys;
	enum smw_config_cipher_mode_id mode_id;
	enum smw_config_cipher_op_type_id op_type_id;
	enum smw_op_step op_step;
	struct smw_cipher_init_args *init_pub;
	struct smw_cipher_data_args *data_pub;
};

/**
 * smw_crypto_get_cipher_iv() - Return the address of the IV buffer
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * address of IV buffer
 * NULL
 */
unsigned char *smw_crypto_get_cipher_iv(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_get_cipher_iv_len() - Return the length of the IV buffer
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * IV buffer length
 * 0
 */
unsigned int smw_crypto_get_cipher_iv_len(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_get_cipher_key_id() - Get cipher key ID set by subsystem
 * @args: Pointer to internal cipher arguments.
 * @idx: Index of the key in the key descriptors array.
 *
 * Return:
 * key ID set by subsystem
 * 0
 */
uint32_t smw_crypto_get_cipher_key_id(struct smw_crypto_cipher_args *args,
				      unsigned int idx);

/**
 * smw_crypto_get_cipher_input() - Get cipher input buffer address
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * address of cipher input buffer
 * NULL
 */
unsigned char *smw_crypto_get_cipher_input(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_get_cipher_input_len() - Return the length of the input buffer
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * input buffer length
 * 0
 */
unsigned int
smw_crypto_get_cipher_input_len(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_get_cipher_output() - Get cipher output buffer address
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * address of cipher output buffer
 * NULL
 */
unsigned char *
smw_crypto_get_cipher_output(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_get_cipher_output_len() - Return the length of the output buffer
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * output buffer length
 * 0
 */
unsigned int
smw_crypto_get_cipher_output_len(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_set_cipher_output_len() - Set cipher output buffer length
 * @args: Pointer to internal cipher arguments.
 * @len: Output buffer length value.
 *
 * Return:
 * none
 */
void smw_crypto_set_cipher_output_len(struct smw_crypto_cipher_args *args,
				      unsigned int len);

/**
 * smw_crypto_get_cipher_init_op_context() - Return cipher init op ctx pointer
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * Address of cipher init operation context structure
 */
struct smw_op_context *
smw_crypto_get_cipher_init_op_context(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_get_cipher_data_op_context() - Return cipher data op ctx ptr
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * Address of cipher data operation context structure
 */
struct smw_op_context *
smw_crypto_get_cipher_data_op_context(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_get_cipher_nb_key_buffer() - Get number of keys defined as buffer
 * @args: Pointer to internal cipher arguments.
 *
 * Return:
 * Number of keys defined as buffer
 */
unsigned int
smw_crypto_get_cipher_nb_key_buffer(struct smw_crypto_cipher_args *args);

/**
 * smw_crypto_cipher_iv_required() - Check if cipher IV/tweak is required
 * @mode: Cipher mode
 *
 * Return:
 * True is required,
 * False otherwise.
 */
static inline bool
smw_crypto_cipher_iv_required(enum smw_config_cipher_mode_id mode)
{
	bool ret = true;

	if (mode == SMW_CONFIG_CIPHER_MODE_ID_ECB ||
	    mode == SMW_CONFIG_CIPHER_MODE_ID_INVALID)
		ret = false;

	return ret;
}

#endif /* __CIPHER_H__ */
