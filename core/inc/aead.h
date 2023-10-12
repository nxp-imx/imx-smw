/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __AEAD_H__
#define __AEAD_H__

#include "config.h"
#include "keymgr.h"
#include "exec.h"
#include "operation_context.h"

/**
 * struct smw_crypto_aead_args - Internal AEAD arguments structure
 * @key_desc: Internal key descriptor structure
 * @mode_id: AEAD mode ID
 * @op_id: Operation type ID
 * @op_step: Multi-part operation step
 * @init_pub: Pointer to the public AEAD init arguments structure
 * @data_pub: Pointer to the public AEAD data arguments structure
 * @tag: Pointer to tag buffer
 * @tag_length: Tag buffer length in bytes
 * @aad: Pointer to additional authentication data
 */
struct smw_crypto_aead_args {
	struct smw_keymgr_descriptor key_desc;
	enum smw_config_aead_mode_id mode_id;
	enum smw_config_aead_op_type_id op_id;
	enum smw_op_step op_step;
	struct smw_aead_init_args *init_pub;
	struct smw_aead_data_args *data_pub;
	unsigned char *tag;
	unsigned int tag_length;
	unsigned char *aad;
};

/**
 * smw_crypto_get_aad() - Get AEAD AAD buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD AAD buffer
 * NULL
 */
unsigned char *smw_crypto_get_aad(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aad_len() - Return the length of the AAD buffer
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * AAD buffer length
 * 0
 */
unsigned int smw_crypto_get_aad_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_iv() - Get IV buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of IV buffer
 * NULL
 */
unsigned char *smw_crypto_get_iv(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_iv_len() - Return the length of the iv buffer
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * iv length
 * 0
 */
unsigned int smw_crypto_get_iv_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_plaintext_len() - Return the length of the plaintext
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * plaintext length
 * 0
 */
unsigned int smw_crypto_get_plaintext_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_input() - Get AEAD input buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD input buffer
 * NULL
 */
unsigned char *smw_crypto_get_input(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_input_len() - Return the length of the input buffer
 * @args: Pointer to internal AEAD argument structure
 *
 * For encryption operation, it returns input data length
 * For decryption operation, it returns ciphertext length + tag length
 *
 * Return:
 * input buffer length
 * 0
 */
unsigned int smw_crypto_get_input_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_output() - Get AEAD output buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD output buffer
 * NULL
 */
unsigned char *smw_crypto_get_output(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_output_len() - Return the length of the output buffer
 * @args: Pointer to internal AEAD arguments
 *
 * For encryption operation, it returns ciphertext length + tag length
 * For decryption operation, it returns data length
 *
 * Return:
 * output buffer length
 * 0
 */
unsigned int smw_crypto_get_output_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_set_output_len() - Set AEAD output buffer length
 * @args: Pointer to internal AEAD arguments
 * @len: Output buffer length value
 *
 * Return:
 * none
 */
void smw_crypto_set_output_len(struct smw_crypto_aead_args *args,
			       unsigned int len);

/**
 * smw_crypto_get_tag() - Get AEAD tag buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD tag buffer
 * NULL
 */
unsigned char *smw_crypto_get_tag(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_tag_len() - Get AEAD tag buffer length
 * @args: Pointer to internal AEAD arguments
 *
 * Return:
 * tag buffer length
 * 0
 */
unsigned int smw_crypto_get_tag_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_set_tag_len() - Set AEAD tag buffer length
 * @args: Pointer to internal AEAD arguments
 * @len: Tag buffer length value
 *
 * Return:
 * none
 */
void smw_crypto_set_tag_len(struct smw_crypto_aead_args *args,
			    unsigned int len);

/**
 * smw_crypto_set_init_op_context() - Set AEAD init context pointer
 * @args: Pointer to internal AEAD arguments.
 * @op_context: Pointer to SMW operation context structure.
 *
 * Return:
 * none
 */
void smw_crypto_set_init_op_context(struct smw_crypto_aead_args *args,
				    struct smw_op_context *op_context);

/**
 * smw_crypto_set_data_op_context() - Set AEAD data context pointer
 * @args: Pointer to internal AEAD arguments.
 * @op_context: Pointer top SMW operation context structure.
 *
 * Return:
 * none
 */
void smw_crypto_set_data_op_context(struct smw_crypto_aead_args *args,
				    struct smw_op_context *op_context);

/**
 * smw_crypto_set_init_handle() - Set AEAD init handle
 * @args: Pointer to internal AEAD arguments.
 * @handle: Pointer to handle.
 *
 * Return:
 * none
 */
void smw_crypto_set_init_handle(struct smw_crypto_aead_args *args,
				void *handle);

/**
 * smw_crypto_get_op_handle() - Get AEAD operation handle
 * @args: Pointer to internal AEAD arguments
 *
 * Return:
 * AEAD operation handle
 * NULL
 */
void *smw_crypto_get_op_handle(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_set_ctx_reserved() - Set AEAD context reserved field
 * @args: Pointer to internal AEAD arguments
 * @rsvd: Pointer to subsystem context operation structure
 *
 * Return:
 * none
 */
void smw_crypto_set_ctx_reserved(struct smw_crypto_aead_args *args,
				 struct smw_crypto_context_ops *rsvd);

#endif /* __AEAD_H__ */
