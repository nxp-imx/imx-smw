/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __ASYMMETRIC_ENCRYPTION_H__
#define __ASYMMETRIC_ENCRYPTION_H__

#include "config.h"
#include "keymgr.h"
#include "exec.h"
#include "smw/crypto/asymmetric_encryption.h"

/**
 * struct smw_asymmetric_encryption_attrs - Asymmetric encryption attr structure
 * @algo_id: Asymmetric encryption algo ID
 * @type_id: Asymmetric encryption mode ID
 * @hash_id: Hash algorithm ID
 */
struct smw_asymmetric_encryption_attrs {
	enum smw_config_asymm_enc_algo_id algo_id;
	enum smw_config_asymm_enc_mode_id mode_id;
	enum smw_config_hash_algo_id hash_id;
};

/**
 * struct smw_crypto_asymm_enc_args - Internal asymmetric encryption arguments
 *                                    structure
 * @key_desc: Internal key descriptor structure
 * @attrs: Asymmetric encryption attributes structure
 * @pub: Pointer to public asymmetric encryption arguments structure
 */
struct smw_crypto_asymm_enc_args {
	struct smw_keymgr_descriptor key_desc;
	struct smw_asymmetric_encryption_attrs attrs;
	struct smw_asymmetric_encryption_args *pub;
};

/**
 * smw_crypto_get_asymm_enc_input() - Get input buffer address
 * @args: Pointer to internal asymmetric encryption arguments structure.
 *
 * Return:
 * address of input buffer
 * NULL
 */
unsigned char *
smw_crypto_get_asymm_enc_input(struct smw_crypto_asymm_enc_args *args);

/**
 * smw_crypto_get_asymm_enc_input_len() - Return the length of the input buffer
 * @args: Pointer to internal asymmetric encryption arguments structure.
 *
 * Return:
 * input buffer length
 * 0
 */
unsigned int
smw_crypto_get_asymm_enc_input_len(struct smw_crypto_asymm_enc_args *args);

/**
 * smw_crypto_get_asymm_enc_output() - Get output buffer address
 * @args: Pointer to internal asymmetric encryption arguments structure.
 *
 * Return:
 * address of output buffer
 * NULL
 */
unsigned char *
smw_crypto_get_asymm_enc_output(struct smw_crypto_asymm_enc_args *args);

/**
 * smw_crypto_get_asymm_enc_output_len() - Return output buffer length
 * @args: Pointer to internal asymmetric encryption arguments structure.
 *
 * Return:
 * output buffer length
 * 0
 */
unsigned int
smw_crypto_get_asymm_enc_output_len(struct smw_crypto_asymm_enc_args *args);

/**
 * smw_crypto_get_asymm_enc_salt() - Get salt buffer address
 * @args: Pointer to internal asymmetric encryption arguments structure.
 *
 * Return:
 * address of salt buffer
 * NULL
 */
unsigned char *
smw_crypto_get_asymm_enc_salt(struct smw_crypto_asymm_enc_args *args);

/**
 * smw_crypto_get_asymm_enc_salt_len() - Return the length of the salt buffer
 * @args: Pointer to internal asymmetric encryption arguments structure.
 *
 * Return:
 * salt buffer length
 * 0
 */
unsigned int
smw_crypto_get_asymm_enc_salt_len(struct smw_crypto_asymm_enc_args *args);

/**
 * smw_crypto_set_asymm_enc_output_len() - Set output buffer length
 * @args: Pointer to internal asymmetric encryption arguments structure.
 * @len: Output buffer length value.
 *
 * Return:
 * none
 */
void smw_crypto_set_asymm_enc_output_len(struct smw_crypto_asymm_enc_args *args,
					 unsigned int len);

#endif /* __ASYMMETRIC_ENCRYPTION_H__ */
