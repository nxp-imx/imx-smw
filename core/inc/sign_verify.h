/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

/* Signature type string */
#define SIGNATURE_TYPE_STR    "SIGNATURE_TYPE"
#define RSASSA_PKCS1_V1_5_STR "RSASSA-PKCS1-V1_5"
#define RSASSA_PSS_STR	      "RSASSA-PSS"

#define SALT_LEN_STR "SALT_LEN"

/* Signature type enum */
enum signature_type {
	SIGNATURE_TYPE_RSASSA_PKCS1_V1_5,
	SIGNATURE_TYPE_RSASSA_PSS,
	SIGNATURE_TYPE_UNDEFINED
};

/**
 * struct smw_sign_verify_attributes - Sign Verify attributes list.
 * @signature_type: Type of signature.
 * @salt_length: Optional salt length in bytes.
 *
 * @salt_length is only for 'RSASSA-PSS' signature type. If not set, the
 * salt length is equal to the hash length.
 */
struct smw_sign_verify_attributes {
	enum signature_type signature_type;
	uint32_t salt_length;
};

/**
 * struct smw_crypto_sign_verify_args - Sign or verify arguments
 * @key_descriptor: Descriptor of the Key
 * @algo_id: Algorithm ID
 * @pub: Pointer to the public API arguments structure
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_crypto_sign_verify_args {
	struct smw_keymgr_descriptor key_descriptor;
	enum smw_config_hash_algo_id algo_id;
	struct smw_sign_verify_args *pub;
	struct smw_sign_verify_attributes attributes;
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
