/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __KEYMGR_H__
#define __KEYMGR_H__

#include <stdint.h>
#include <stdbool.h>

#include "config.h"

/*
 * Hardcoded values due to limitation of SMW's HSM subsystem support. Transient
 * and persistent keys can't be part of the same key group and user can't set
 * the key group ID.
 * May have to be change in other version.
 */
#define PERSISTENT_KEY_GROUP 0
#define TRANSIENT_KEY_GROUP  1

/* Define invalid key identifier */
#define INVALID_KEY_ID 0

/* Default RSA public exponent is 65537, which has a length of 3 bytes */
#define DEFAULT_RSA_PUB_EXP_LEN 3

#define PERSISTENT_STR	   "PERSISTENT"
#define RSA_PUB_EXP_STR	   "RSA_PUB_EXP"
#define FLUSH_KEY_STR	   "FLUSH_KEY"
#define POLICY_STR	   "POLICY"
#define USAGE_STR	   "USAGE"
#define EXPORT_STR	   "EXPORT"
#define COPY_STR	   "COPY"
#define ENCRYPT_STR	   "ENCRYPT"
#define DECRYPT_STR	   "DECRYPT"
#define SIGN_MESSAGE_STR   "SIGN_MESSAGE"
#define VERIFY_MESSAGE_STR "VERIFY_MESSAGE"
#define SIGN_HASH_STR	   "SIGN_HASH"
#define VERIFY_HASH_STR	   "VERIFY_HASH"
#define DERIVE_STR	   "DERIVE"
#define ALGO_STR	   "ALGO"
#define HASH_STR	   "HASH"
#define KDF_STR		   "KDF"
#define LENGTH_STR	   "LENGTH"
#define MIN_LENGTH_STR	   "MIN_LENGTH"

#define ANY_STR			    "ANY"
#define ALL_CIPHER_STR		    "ALL_CIPHER"
#define HMAC_STR		    "HMAC"
#define CBC_MAC_STR		    "CBC_MAC"
#define CMAC_STR		    "CMAC"
#define STREAM_CIPHER_STR	    "STREAM_CIPHER"
#define CTR_STR			    "CTR"
#define CFB_STR			    "CFB"
#define OFB_STR			    "OFB"
#define XTS_STR			    "XTS"
#define ECB_NO_PADDING_STR	    "ECB_NO_PADDING"
#define CBC_NO_PADDING_STR	    "CBC_NO_PADDING"
#define CBC_PKCS7_STR		    "CBC_PKCS7"
#define CCM_STR			    "CCM"
#define GCM_STR			    "GCM"
#define CHACHA20_POLY1305_STR	    "CHACHA20_POLY1305"
#define HKDF_STR		    "HKDF"
#define TLS12_PRF_STR		    "TLS12_PRF"
#define TLS12_PSK_TO_MS_STR	    "TLS12_PSK_TO_MS"
#define PBKDF2_HMAC_STR		    "PBKDF2_HMAC"
#define PBKDF2_AES_CMAC_PRF_128_STR "PBKDF2_AES_CMAC_PRF_128"
#define RSA_PKCS1V15_STR	    "RSA_PKCS1V15"
#define RSA_PSS_STR		    "RSA_PSS"
#define RSA_PSS_ANY_SALT_STR	    "RSA_PSS_ANY_SALT"
#define ECDSA_STR		    "ECDSA"
#define DETERMINISTIC_ECDSA_STR	    "DETERMINISTIC_ECDSA"
#define PURE_EDDSA_STR		    "PURE_EDDSA"
#define ED25519PH_STR		    "ED25519PH"
#define ED448PH_STR		    "ED448PH"
#define RSA_PKCS1V15_CRYPT_STR	    "RSA_PKCS1V15_CRYPT"
#define RSA_OAEP_STR		    "RSA_OAEP"
#define ECDH_STR		    "ECDH"
#define FFDH_STR		    "FFDH"
#define MD2_STR			    "MD2"
#define MD4_STR			    "MD4"
#define MD5_STR			    "MD5"
#define RIPEMD160_STR		    "RIPEMD160"
#define SHA_1_STR		    "SHA1"
#define SHA_224_STR		    "SHA224"
#define SHA_256_STR		    "SHA256"
#define SHA_384_STR		    "SHA384"
#define SHA_512_STR		    "SHA512"
#define SHA_512_224_STR		    "SHA512_224"
#define SHA_512_256_STR		    "SHA512_256"
#define SHA3_224_STR		    "SHA3_224"
#define SHA3_256_STR		    "SHA3_256"
#define SHA3_384_STR		    "SHA3_384"
#define SHA3_512_STR		    "SHA3_512"
#define SHAKE256_512_STR	    "SHAKE256_512"
#define SM3_STR			    "SM3"

enum smw_keymgr_privacy_id {
	/* Key privacy */
	SMW_KEYMGR_PRIVACY_ID_PUBLIC,
	SMW_KEYMGR_PRIVACY_ID_PRIVATE,
	SMW_KEYMGR_PRIVACY_ID_PAIR,
	SMW_KEYMGR_PRIVACY_ID_NB,
	SMW_KEYMGR_PRIVACY_ID_INVALID
};

enum smw_keymgr_format_id {
	/* Key format */
	SMW_KEYMGR_FORMAT_ID_HEX,
	SMW_KEYMGR_FORMAT_ID_BASE64,
	SMW_KEYMGR_FORMAT_ID_NB,
	SMW_KEYMGR_FORMAT_ID_INVALID
};

/**
 * struct smw_keymgr_identifier - Key identifier
 * @subsystem_id: Secure Subsystem ID
 * @type_id: Key type ID
 * @privacy_id: Key privacy ID
 * @attribute: Key attribute
 * @security_size: Security size in bits
 * @id: Key ID set by the subsystem
 * @persistent: Is persistent or transient key
 *
 * The value of @attribute is key type dependent.
 * For RSA key type, it represents the public exponent length in bytes.
 */
struct smw_keymgr_identifier {
	enum subsystem_id subsystem_id;
	enum smw_config_key_type_id type_id;
	enum smw_keymgr_privacy_id privacy_id;
	unsigned int attribute;
	unsigned int security_size;
	uint32_t id;
	bool persistent;
};

/**
 * struct smw_keymgr_key_ops - keypair with operations
 * @keys: Public API Keypair
 * @public_data: Get the @pub's public data reference
 * @public_length: Get the @pub's public length reference
 * @private_data: Get the @pub's private data reference
 * @private_length: Get the @pub's private length reference
 * @modulus: Get the @pub's modulus reference
 * @modulus_length: Get the @pub's modulus length reference
 *
 * This structure is initialized by the function
 * smw_keymgr_convert_descriptor().
 * The operations are function of the keypair object defined by the
 * key type.
 */
struct smw_keymgr_key_ops {
	struct smw_keypair_buffer *keys;

	unsigned char **(*public_data)(struct smw_keymgr_key_ops *this);
	unsigned int *(*public_length)(struct smw_keymgr_key_ops *this);
	unsigned char **(*private_data)(struct smw_keymgr_key_ops *this);
	unsigned int *(*private_length)(struct smw_keymgr_key_ops *this);
	unsigned char **(*modulus)(struct smw_keymgr_key_ops *this);
	unsigned int *(*modulus_length)(struct smw_keymgr_key_ops *this);
};

/**
 * struct smw_keymgr_descriptor - Key descriptor
 * @identifier: Key identifier
 * @format_id: Format ID of the Key buffers
 * @pub: Key descriptor from the public API
 * @ops: Keypair operations
 */
struct smw_keymgr_descriptor {
	struct smw_keymgr_identifier identifier;
	enum smw_keymgr_format_id format_id;
	struct smw_key_descriptor *pub;
	struct smw_keymgr_key_ops ops;
};

/**
 * struct smw_keymgr_attributes - Key attributes list.
 * @persistent_storage: Use persistent subsystem storage or not.
 * @rsa_pub_exp: Pointer to rsa public exponent.
 * @rsa_pub_exp_len: @rsa_pub_exp length in bytes.
 * @flush_key: Flush persistent key(s)
 * @policy: Key policy encoded as variable-length list TLV.
 * @policy_len: @policy length in bytes.
 * @pub_key_attributes_list: Key attributes list from the public API
 * @pub_key_attributes_list_length: Length of @pub_key_attributes_list
 */
struct smw_keymgr_attributes {
	bool persistent_storage;
	unsigned char *rsa_pub_exp;
	unsigned int rsa_pub_exp_len;
	bool flush_key;
	unsigned char *policy;
	unsigned int policy_len;
	unsigned char *pub_key_attributes_list;
	unsigned int *pub_key_attributes_list_length;
};

/**
 * struct smw_keymgr_generate_key_args - Key generation arguments
 * @key_attributes: Key attributes
 * @key_descriptor: Descriptor of the generated Key
 *
 */
struct smw_keymgr_generate_key_args {
	struct smw_keymgr_attributes key_attributes;
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * struct smw_keymgr_update_key_args - Key update arguments
 *
 */
struct smw_keymgr_update_key_args {
	//TODO: define smw_keymgr_update_key_args
	int dummy;
};

/**
 * struct smw_keymgr_import_key_args - Key import arguments
 * @key_attributes: Key attributes
 * @key_descriptor: Descriptor of the imported Key
 *
 */
struct smw_keymgr_import_key_args {
	struct smw_keymgr_attributes key_attributes;
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * struct smw_keymgr_export_key_args - Key export arguments
 * @key_descriptor: Descriptor of the exported Key
 *
 */
struct smw_keymgr_export_key_args {
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * struct smw_keymgr_delete_key_args - Key deletion arguments
 * @key_descriptor: Descriptor of the Key to delete
 *
 */
struct smw_keymgr_delete_key_args {
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * smw_keymgr_alloc_keypair_buffer() - Allocate a keypair object.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @public_length: Length of the public Key buffer.
 * @private_length: Length of the private Key buffer.
 *
 * This function allocates a keypair buffer object and
 * the keys buffers (public/private) if corresponding lengths are set.
 *
 * Return:
 * error code.
 */
int smw_keymgr_alloc_keypair_buffer(struct smw_keymgr_descriptor *descriptor,
				    unsigned int public_length,
				    unsigned int private_length);

/**
 * smw_keymgr_free_keypair_buffer() - Free a keypair object.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function frees the memory allocated by
 * smw_keymgr_alloc_keypair_buffer().
 *
 * Return:
 * error code.
 */
int smw_keymgr_free_keypair_buffer(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_api_key_id() - Return the API key descriptor id value.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the value of the API key descriptor id value.
 *
 * Return:
 * key descriptor id
 */
unsigned int
smw_keymgr_get_api_key_id(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_public_data() - Return the address of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the address of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns NULL.
 *
 * Return:
 * NULL
 * address of the public Key buffer
 */
unsigned char *
smw_keymgr_get_public_data(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_public_length() - Return the length of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the length of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns 0.
 *
 * Return:
 * 0
 * length of the public Key buffer.
 */
unsigned int
smw_keymgr_get_public_length(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_private_data() - Return the address of the private Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the address of the private Key buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns NULL.
 *
 * Return:
 * NULL
 * address of the private Key buffer
 */
unsigned char *
smw_keymgr_get_private_data(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_private_length() - Return the length of the private Key
 *                                   buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the length of the private Key buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns 0.
 *
 * Return:
 * 0
 * length of the private Key buffer.
 */
unsigned int
smw_keymgr_get_private_length(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_modulus() - Return the address of the modulus buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the address of the modulus buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns NULL.
 *
 * Return:
 * NULL
 * address of the modulus buffer.
 */
unsigned char *smw_keymgr_get_modulus(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_modulus_length() - Return the length of the modulus buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the length of the modulus buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns 0.
 *
 * Return:
 * 0
 * length of the mofulus Key buffer.
 */
unsigned int
smw_keymgr_get_modulus_length(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_set_public_data() - Set the address of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @public_data: Address of the public Key buffer.
 *
 * This function sets the address of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_public_data(struct smw_keymgr_descriptor *descriptor,
				unsigned char *public_data);

/**
 * smw_keymgr_set_public_length() - Set the length of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @public_length: Length of the public Key buffer.
 *
 * This function sets the length of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_public_length(struct smw_keymgr_descriptor *descriptor,
				  unsigned int public_length);

/**
 * smw_keymgr_set_private_data() - Set the address of the private Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @private_data: Address of the private Key buffer.
 *
 * This function sets the address of the private Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_private_data(struct smw_keymgr_descriptor *descriptor,
				 unsigned char *private_data);

/**
 * smw_keymgr_set_private_length() - Set the length of the private Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @private_length: Length of the private Key buffer.
 *
 * This function sets the length of the private Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_private_length(struct smw_keymgr_descriptor *descriptor,
				   unsigned int private_length);

/**
 * smw_keymgr_set_modulus_length() - Set the length of the modulus buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @modulus_length: Length of the modulus buffer.
 *
 * This function sets the length of the modulus buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_modulus_length(struct smw_keymgr_descriptor *descriptor,
				   unsigned int modulus_length);

/**
 * smw_keymgr_get_buffers_lengths() - Get the lengths of the Key buffers.
 * @identifier: Pointer to key identifier structure.
 * @format_id: Format ID.
 * @public_buffer_length: Pointer to the public buffer length.
 * @private_buffer_length: Pointer to the private buffer length.
 * @modulus_buffer_length: Pointer to the modulus buffer length (RSA key).
 *
 * This function computes the lengths of the Key buffers.
 *
 * Return:
 * error code.
 */
int smw_keymgr_get_buffers_lengths(struct smw_keymgr_identifier *identifier,
				   enum smw_keymgr_format_id format_id,
				   unsigned int *public_buffer_length,
				   unsigned int *private_buffer_length,
				   unsigned int *modulus_buffer_length);

/**
 * smw_keymgr_convert_descriptor() - Key descriptor conversion.
 * @in: Pointer to a public Key descriptor.
 * @out: Pointer to an internal Key descriptor.
 *
 * This function converts a public Key descriptor
 * into an internal Key descriptor.
 *
 * Return:
 * error code.
 */
int smw_keymgr_convert_descriptor(struct smw_key_descriptor *in,
				  struct smw_keymgr_descriptor *out);

/**
 * smw_keymgr_set_default_attributes() - Set default Key attributes.
 * @attr: Pointer to the Key attributes structure.
 *
 * This function sets the default values of the Key attributes.
 *
 * Return:
 * None.
 */
void smw_keymgr_set_default_attributes(struct smw_keymgr_attributes *attr);

/**
 * smw_keymgr_read_attributes() - Read key attributes from list
 * @key_attrs: Key attributes read.
 * @attr_list: List (TLV string format) of attributes to read.
 * @attr_length: Length of the @att_list string.
 *
 * This function reads the TLV string @attr_list and set appropriate
 * key attributes in @key_attrs structure.
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - One of the parameters is invalid.
 */
int smw_keymgr_read_attributes(struct smw_keymgr_attributes *key_attrs,
			       unsigned char *attr_list,
			       unsigned int *attr_length);

/**
 * smw_keymgr_set_attributes_list() - Set Key attributes.
 * @key_attrs: Key attributes.
 * @attr_list: List (TLV string format) of attributes to write.
 * @attr_length: Length of the @att_list string.
 *
 * This function sets the Key attributes list.
 *
 * Return:
 * None.
 */
void smw_keymgr_set_attributes_list(struct smw_keymgr_attributes *key_attrs,
				    unsigned char *attr_list,
				    unsigned int attr_length);

/**
 * smw_keymgr_get_privacy_id() - Get the Key privacy ID.
 * @type_id: Key type ID.
 * @privacy_id: Key privacy ID.
 *
 * This function gets the Key privacy ID given the Key type ID.
 *
 * Return:
 * error code.
 */
int smw_keymgr_get_privacy_id(enum smw_config_key_type_id type_id,
			      enum smw_keymgr_privacy_id *privacy_id);

#endif /* __KEYMGR_H__ */
