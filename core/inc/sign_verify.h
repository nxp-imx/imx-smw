/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SIGN_VERIFY_H__
#define __SIGN_VERIFY_H__

#include "smw/attr.h"

#include "keymgr.h"
#include "config.h"
#include "operation_step.h"
#include "operation_context.h"

#define DEFAULT_STR "DEFAULT"

/* Signature algo strings */
#define ECDSA_STR   "ECDSA"
#define EDDSA_STR   "EDDSA"
#define DSA_STR	    "DSA"
#define RSA_STR	    "RSA"
#define TLS_1_2_STR "TLS_1_2"

/* Signature type strings */
#define PKCS1_1_5_STR  "PKCS1_1_5"
#define PSS_STR	       "PSS"
#define CLIENT_STR     "CLIENT"
#define SERVER_STR     "SERVER"
#define CMAC_STR       "CMAC"
#define PURE_EDDSA_STR "PURE_EDDSA"
#define EDDSA_PH_STR   "EDDSA_PH"
#define EDDSA_CTX_STR  "EDDSA_CTX"

/**
 * struct smw_sign_verify_attributes - Sign Verify attributes.
 * @algo_id: Signature algo ID
 * @type_id: Signature type ID
 * @hash_id: Hash algorithm ID
 * @salt_length: Optional salt length in bytes.
 * @msg_hashed: True if input message is already hashed.
 *
 * Parameter @salt_length is only for 'RSA' signature type. If not set,
 * the salt length is equal to the hash length.
 */
struct smw_sign_verify_attributes {
	enum smw_config_sign_algo_id algo_id;
	enum smw_config_sign_type_id type_id;
	enum smw_config_hash_algo_id hash_id;
	uint32_t salt_length;
	bool msg_hashed;
};

/**
 * struct smw_crypto_sign_verify_args - Sign or verify arguments
 * @key_descriptor: Descriptor of the Key
 * @attributes: Signature attributes
 * @op_step: Multi-part operation step
 * @one_shot_pub: Pointer to the public API one-shot arguments structure
 * @init_pub: Pointer to the public API initialization arguments structure
 * @update_pub: Pointer to the public API update arguments structure
 * @final_pub: Pointer to the public API final arguments structure
 *
 */
struct smw_crypto_sign_verify_args {
	struct smw_keymgr_descriptor key_descriptor;
	struct smw_sign_verify_attributes attributes;
	enum smw_op_step op_step;
	union {
		struct smw_sign_verify_args *oneshot_pub;
		struct smw_sign_verify_init_args *init_pub;
		struct smw_sign_verify_update_args *update_pub;
		struct smw_sign_verify_final_args *final_pub;
	};
};

/**
 * smw_sign_verify_get_msg_buf() - Return the message buffer.
 * @args: Pointer to the internal Sign/Verify args structure.
 *
 * This function returns the address of the Sign/Verify message buffer.
 *
 * Return:
 * NULL
 * address of the Sign/Verify message buffer.
 */
unsigned char *
smw_sign_verify_get_msg_buf(struct smw_crypto_sign_verify_args *args);

/**
 * smw_sign_verify_get_msg_len() - Return the message length.
 * @args: Pointer to the internal Sign/Verify args structure.
 *
 * This function returns the length of the Sign/Verify message buffer.
 *
 * Return:
 * 0
 * length of the Sign/Verify message buffer.
 */
unsigned int
smw_sign_verify_get_msg_len(struct smw_crypto_sign_verify_args *args);

/**
 * smw_sign_verify_get_sign_buf() - Return the signature buffer.
 * @args: Pointer to the internal Sign/Verify args structure.
 *
 * This function returns the address of the Sign/Verify signature buffer.
 *
 * Return:
 * NULL
 * address of the Sign/Verify signature buffer.
 */
unsigned char *
smw_sign_verify_get_sign_buf(struct smw_crypto_sign_verify_args *args);

/**
 * smw_sign_verify_get_sign_len() - Return the signature length.
 * @args: Pointer to the internal Sign/Verify args structure.
 *
 * This function returns the length of the Sign/Verify signature buffer.
 *
 * Return:
 * 0
 * length of the Sign/Verify signature buffer.
 */
unsigned int
smw_sign_verify_get_sign_len(struct smw_crypto_sign_verify_args *args);

/**
 * smw_sign_verify_copy_sign_buf() - Copy the signature buffer.
 * @args: Pointer to the internal Sign/Verify args structure.
 * @signature_buffer: Sign/Verify signature buffer.
 * @signature_length: Length of the Sign/Verify signature buffer.
 *
 * This function copies the Sign/Verify signature buffer
 * to the public API structure.
 *
 * Return:
 * none.
 */
void smw_sign_verify_copy_sign_buf(struct smw_crypto_sign_verify_args *args,
				   unsigned char *signature,
				   unsigned int signature_length);

/**
 * smw_sign_verify_set_sign_len() - Set the signature length.
 * @args: Pointer to the internal Sign/Verify args structure.
 * @signature_length: Length of the Sign/Verify signature buffer.
 *
 * This function sets the length of the Sign/Verify signature buffer.
 *
 * Return:
 * none.
 */
void smw_sign_verify_set_sign_len(struct smw_crypto_sign_verify_args *args,
				  unsigned int signature_length);

/**
 * smw_sign_verify_get_eddsa_param() - Return the eddsa context parameters.
 * @args: Pointer to the internal Sign/Verify args structure.
 *
 * This function returns the Sign/Verify eddsa context parameters.
 *
 * Return:
 * NULL
 * address of the Sign/Verify eddsa context parameters.
 */
struct smw_eddsa_params *
smw_sign_verify_get_eddsa_context(struct smw_crypto_sign_verify_args *args);

/**
 * smw_sing_verify_get_op_context() - Get signature operation context pointer
 * @args: Pointer to internal signature arguments.
 *
 * Return:
 * Address of operation context structure
 */
struct smw_op_context *
smw_sign_verify_get_op_context(struct smw_crypto_sign_verify_args *args);

#endif /* __SIGN_VERIFY_H__ */
