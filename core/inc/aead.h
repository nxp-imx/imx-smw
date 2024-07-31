/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */

#ifndef __AEAD_H__
#define __AEAD_H__

#include "subsystems.h"
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
 * @tag: Pointer to tag buffer
 * @oneshot_pub: Pointer to public AEAD one-shot arguments structure
 * @init_pub: Pointer to public AEAD initialization arguments structure
 * @data_pub: Pointer to public AEAD data arguments structure
 * @aad_pub: Pointer to public AEAD AAD arguments structure
 * @final_pub: Pointer to public AEAD final arguments structure
 *
 * The @tag field dynamically points to the tag value.
 * It either points to dedicated tag field if it is explicitly set,
 * or points to tag set in the @data.output field in case of encryption or
 * tag set in the @data.input field in case of decryption.
 *
 */
struct smw_crypto_aead_args {
	struct smw_keymgr_descriptor key_desc;
	enum smw_config_aead_mode_id mode_id;
	enum smw_config_aead_op_type_id op_type_id;
	enum smw_op_step op_step;
	unsigned char *tag;
	union {
		struct smw_aead_args *oneshot_pub;
		struct smw_aead_init_args *init_pub;
		struct smw_aead_data_args *data_pub;
		struct smw_aead_aad_args *aad_pub;
		struct smw_aead_final_args *final_pub;
	};
};

/**
 * smw_crypto_get_aead_aad() - Get AEAD AAD buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD AAD buffer
 * NULL
 */
unsigned char *smw_crypto_get_aead_aad(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_aad_len() - Return the length of the AAD buffer
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * AAD buffer length
 * 0
 */
unsigned int smw_crypto_get_aead_aad_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_iv() - Get IV buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of IV buffer
 * NULL
 */
unsigned char *smw_crypto_get_aead_iv(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_iv_len() - Return the length of the IV buffer
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * IV buffer length
 * 0
 */
unsigned int smw_crypto_get_aead_iv_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_output_iv() - Get output IV buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of output IV buffer
 * NULL
 */
unsigned char *smw_crypto_get_aead_output_iv(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_output_iv_len() - Return the length of the output IV buffer
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * output IV length
 * 0
 */
unsigned int
smw_crypto_get_aead_output_iv_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_plaintext_len() - Return the length of the plaintext
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * plaintext length
 * 0
 */
unsigned int
smw_crypto_get_aead_plaintext_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_input() - Get AEAD input buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD input buffer
 * NULL
 */
unsigned char *smw_crypto_get_aead_input(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_input_len() - Return the length of the input buffer
 * @args: Pointer to internal AEAD argument structure
 *
 * For encryption operation, it returns input data length
 * For decryption operation, it returns ciphertext length + tag length
 *
 * Return:
 * input buffer length
 * 0
 */
unsigned int smw_crypto_get_aead_input_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_output() - Get AEAD output buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD output buffer
 * NULL
 */
unsigned char *smw_crypto_get_aead_output(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_output_len() - Return the length of the output buffer
 * @args: Pointer to internal AEAD arguments
 *
 * For encryption operation, it returns ciphertext length + tag length
 * For decryption operation, it returns data length
 *
 * Return:
 * output buffer length
 * 0
 */
unsigned int smw_crypto_get_aead_output_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_set_aead_output_len() - Set AEAD output buffer length
 * @args: Pointer to internal AEAD arguments
 * @len: Output buffer length value
 *
 * Return:
 * none
 */
void smw_crypto_set_aead_output_len(struct smw_crypto_aead_args *args,
				    unsigned int len);

/**
 * smw_crypto_get_aead_tag() - Get AEAD tag buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Return:
 * address of AEAD tag buffer
 * NULL
 */
unsigned char *smw_crypto_get_aead_tag(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_is_aead_tag_field_set() - Return true if AEAD tag buffer is set
 * @args: Pointer to internal AEAD argument structure
 *
 * Check if AEAD tag buffer is set in the dedicated tag field
 *
 * Return:
 * * true:	- if dedicated @tag field is set
 * * false:	- if dedicated @tag field is not set
 */
bool smw_crypto_is_aead_tag_field_set(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_tag_len() - Get AEAD tag buffer length
 * @args: Pointer to internal AEAD arguments
 *
 * Return:
 * tag buffer length
 * 0
 */
unsigned int smw_crypto_get_aead_tag_len(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_set_aead_tag_len() - Set AEAD tag buffer length
 * @args: Pointer to internal AEAD arguments
 * @len: Tag buffer length value
 *
 * Return:
 * none
 */
void smw_crypto_set_aead_tag_len(struct smw_crypto_aead_args *args,
				 unsigned int len);

/**
 * smw_crypto_set_aead_output_iv_len() - Set AEAD output IV buffer length
 * @args: Pointer to internal AEAD arguments
 * @len: Output IV buffer length value
 *
 * Return:
 * none
 */
void smw_crypto_set_aead_output_iv_len(struct smw_crypto_aead_args *args,
				       unsigned int len);

/**
 * smw_crypto_get_aead_init_op_context() - Get AEAD init operation context pointer
 * @args: Pointer to internal AEAD arguments.
 *
 * Return:
 * Address of AEAD init operation context structure
 */
struct smw_op_context *
smw_crypto_get_aead_init_op_context(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_data_op_context() - Get AEAD data operation context pointer
 * @args: Pointer to internal AEAD arguments.
 *
 * This function returns the address of AEAD data operation context structure
 * for multi-part update and final operations.
 *
 * Return:
 * Address of AEAD data operation context structure
 */
struct smw_op_context *
smw_crypto_get_aead_data_op_context(struct smw_crypto_aead_args *args);

/**
 * smw_crypto_get_aead_aad_op_context() - Get AEAD AAD operation context pointer
 * @args: Pointer to internal AEAD arguments.
 *
 * This function returns the address of AEAD AAD operation context structure
 * for multi-part update AAD operation.
 *
 * Return:
 * Address of AEAD AAD operation context structure
 */
struct smw_op_context *
smw_crypto_get_aead_aad_op_context(struct smw_crypto_aead_args *args);

#endif /* __AEAD_H__ */
