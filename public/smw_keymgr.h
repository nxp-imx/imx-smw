/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2025 NXP
 */

#ifndef __SMW_KEYMGR_H__
#define __SMW_KEYMGR_H__

#include <stdbool.h>

#include "smw_status.h"
#include "smw/attr.h"
#include "smw/names.h"

/*
 * Define the NXP and NXP's EdgeLock 2GO key/data storage identifier
 * bit[23]    = PSA Vendor bit
 * bit[22]    = Vendor NXP identifier
 * bit[21]    = NXP's EdgeLock 2GO identifier
 * bit[20:16] = Reserved must be 0
 * bit[15]    = Key/Data object (Key=0/Data=1)
 * bit[14:8]  = NXP's enclave storage ID
 * bit[7:0]   = NPX's enclave identifier
 */
#define NXP_KEY_DATA_STORAGE_ID_MASK (BIT(23) | BIT(22))
#define NXP_EL2GO_STORAGE_ID_MASK    (NXP_KEY_DATA_STORAGE_ID_MASK | BIT(21))
#define NXP_EL2GO_KEY		     NXP_EL2GO_STORAGE_ID_MASK
#define NXP_EL2GO_DATA		     (NXP_EL2GO_STORAGE_ID_MASK | BIT(15))
#define NXP_IS_EL2GO_OBJECT(val)     ((val) & (NXP_EL2GO_STORAGE_ID_MASK | BIT(15)))
#define NXP_IS_EL2GO_KEY(val)	     (NXP_IS_EL2GO_OBJECT(val) == NXP_EL2GO_KEY)
#define NXP_IS_EL2GO_DATA(val)	     (NXP_IS_EL2GO_OBJECT(val) == NXP_EL2GO_DATA)

/**
 * struct smw_keypair_gen - Generic Keypair object
 * @public_data: Pointer to the public key
 * @public_length: Length of @public_data in bytes
 * @private_data: Pointer to the private key
 * @private_length: Length of @private_data in bytes
 *
 * Asymmetric Keypair common structure definition. It's the basis of the
 * other asymmetric keypair structure.
 */
struct smw_keypair_gen {
	unsigned char *public_data;
	unsigned int public_length;
	unsigned char *private_data;
	unsigned int private_length;
};

/**
 * struct smw_keypair_rsa - RSA Keypair object
 * @public_data: Pointer to the RSA public exponent
 * @public_length: Length of @public_data in bytes
 * @private_data: Pointer to the RSA private exponent
 * @private_length: Length of @private_data in bytes
 * @modulus: Pointer to the RSA modulus
 * @modulus_length: Length of @modulus in bytes
 * @public_exponent: Pointer to the RSA public exponent
 * @public_exponent_length: Length of @public_exponent in bytes
 *
 * First fields are common to the struct smw_keypair_gen and must be
 * kept common.
 */
struct smw_keypair_rsa {
	unsigned char *public_data;
	unsigned int public_length;
	unsigned char *private_data;
	unsigned int private_length;
	unsigned char *modulus;
	unsigned int modulus_length;
	unsigned char *public_exponent;
	unsigned int public_exponent_length;
};

/**
 * struct smw_keypair_buffer - Keypair buffer
 * @format_name: Defines the encoding format of all buffers.
 *		 See &typedef smw_key_format_t
 * @gen: Generic keypair object definition. See &struct smw_keypair_gen
 * @rsa: RSA keypair object definition. See &struct smw_keypair_rsa
 *
 * By default if format name is not specified,
 * there will be no encoding (equivalent to "HEX")
 */
struct smw_keypair_buffer {
	smw_key_format_t format_name;
	union {
		struct smw_keypair_gen gen;
		struct smw_keypair_rsa rsa;
	};
};

/**
 * struct smw_key_descriptor - Key descriptor
 * @type_name: Key type name. See &typedef smw_key_type_t
 * @security_size: Security size in bits
 * @id: Key identifier
 * @buffer: Key pair buffer. See &struct smw_keypair_buffer
 */
struct smw_key_descriptor {
	smw_key_type_t type_name;
	unsigned int security_size;
	unsigned int id;
	struct smw_keypair_buffer *buffer;
};

/**
 * struct smw_derived_key_descriptor - Derived key descriptor structure
 * @type_name: Key type name. See &typedef smw_key_type_t
 * @security_size: Security size in bits
 * @id: Key identifier
 * @format_name: Defines the encoding format of shared secret buffer
 *		 See &typedef smw_key_format_t
 * @shared_secret: Shared secret buffer
 * @shared_secret_len: @shared_secret length in bytes
 */
struct smw_derived_key_descriptor {
	smw_key_type_t type_name;
	unsigned int security_size;
	unsigned int id;
	smw_key_format_t format_name;
	unsigned char *shared_secret;
	unsigned int shared_secret_len;
};

/**
 * struct smw_key_attributes - Key attributes
 * @permitted_algo: Permitted algorithm. See &typedef smw_attr_algo_t
 * @usage_flags: Permitted usage flags. See &typedef smw_attr_usage_t
 * @storage_id: Storage identifier. See &typedef smw_attr_storage_id_t
 * @attributes: Attributes. See &typedef smw_attr_attributes_t
 */
struct smw_key_attributes {
	smw_attr_algo_t permitted_algo;
	smw_attr_usage_t usage_flags;
	smw_attr_storage_id_t storage_id;
	smw_attr_attributes_t attributes;
};

/**
 * struct smw_generate_key_args - Key generation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_attributes: Pointer to a Key attributes object. See &smw_key_attributes
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * The @key_descriptor fields @type_name and @security_size must be given
 * as input to know the type of key to generate.
 * The @key_descriptor field @buffer is optional. Only the public key will be
 * returned if the corresponding pointer and size are set.
 * The @key_descriptor field @id, if set by the caller (other than 0) will be
 * the created key identifier on operation success. Else the API will returned
 * a new key identifier if @id is set as 0.
 */
struct smw_generate_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_attributes *key_attributes;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_derive_key_args - Key derivation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @kdf_name: Key derivation function name. See &typedef smw_kdf_t
 * @kdf_arguments: Key derivation function arguments
 * @store_derived_key: If true, store the derived key.
 * @key_descriptor_base: Pointer to a Key base descriptor.
 *			 See &struct smw_key_descriptor
 * @key_attributes: Pointer to a Key attributes object. See &smw_key_attributes
 * @key_descriptor_derived: Pointer to the Key derived descriptor structure.
 *			    See &struct smw_derived_key_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is set to SMW_SUBSYSTEM_NAME_NONE, the default Secure Subsystem
 * configured for this Security Operation is used.
 *
 * A new key is derived from a given key base (@key_descriptor_base) using
 * the key derivation function @kdf_name.
 * If the key derivation function requires more arguments,
 * the @kdf_arguments refers to the associated key derivation function
 * arguments, else this pointer is not used and can be NULL.
 *
 * Upon successful completion of the key derivation operation, if
 * @store_derived_key is set to true, new key ID
 * is set in the @key_descriptor_derived->id and shared secret data is exported
 * if @key_descriptor_derived->shared_secret and
 * @key_descriptor_derived->shared_secret_len are set. Refer to the subsystem
 * capabilities for more details.
 */
struct smw_derive_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_kdf_t kdf_name;
	void *kdf_arguments;
	bool store_derived_key;
	struct smw_key_descriptor *key_descriptor_base;
	struct smw_key_attributes *key_attributes;
	struct smw_derived_key_descriptor *key_descriptor_derived;
};

/**
 * struct smw_kdf_tls12_args - Key derivation function TLS 1.2 arguments
 * @key_exchange_name: Name of the key exchange algorithm.
 *                     See &typedef smw_tls12_kea_t
 * @encryption_name: Name of the encryption algorithm.
 *                   See &typedef smw_tls12_enc_t
 * @prf_name: Name of the Pseudo-Random Function (PRF).
 *            See &typedef smw_hash_algo_t
 * @ext_master_key: If true, generates an extended master secret key
 * @kdf_input: Key derivation input data used to generate the master secret key
 * @kdf_input_length: Length in bytes of the @kdf_input buffer
 * @master_sec_key_id: Generated master key identifier
 * @client_w_enc_key_id: Generated client write encryption key identifier
 * @server_w_enc_key_id: Generated server write encryption key identifier
 * @client_w_mac_key_id: Generated client write MAC key identifier (see note 1)
 * @server_w_mac_key_id: Generated server write MAC key identifier (see note 1)
 * @client_w_iv: Pointer to the Client IV buffer (see note 2)
 * @client_w_iv_length: Length of @client_w_iv in bytes (see note 2)
 * @server_w_iv: Pointer to the Server IV buffer (see note 2)
 * @server_w_iv_length: Length of @server_w_iv in bytes (see note 2)
 *
 * This structure defines the additional arguments needed for the TLS 1.2
 * Key derivation (&smw_derive_key_args->kdf_name = `TLS12_KEY_EXCHANGE`).
 *
 * Note 1: Client/Server write MAC key are not generated with AES GCM cipher
 *         encryption.
 * Note 2: Client/Server write IVs are generated only in case of Authentication
 *         Encryption with Additional Data Cipher mode (like AES CCM or GCM).
 *
 * The key derivation &smw_derive_key_args->key_descriptor_derived is filled
 * only if the @key_exchange_name request for an ephemeral public key.
 * Following &smw_derive_key_args->key_descriptor_derived fields are filled:
 *
 *  - @id: set to 0
 *  - @type_name: Set the key type name
 *  - @security_size: Size in bits of the derived key
 *  - @shared_secret: Shared secret buffer
 *  - @shared_secret_len: Shared secret buffer length
 *
 * **WARNING**
 *	This structure is deprecated and will be removed in a future library
 *	release. Please use the new @smw_kdf_tls12_op_args API instead.
 */
struct smw_kdf_tls12_args {
	// Input parameters
	smw_tls12_kea_t key_exchange_name;
	smw_tls12_enc_t encryption_name;
	smw_hash_algo_t prf_name;
	bool ext_master_key;
	unsigned char *kdf_input;
	unsigned int kdf_input_length;
	// Output parameters
	unsigned int master_sec_key_id;
	unsigned int client_w_enc_key_id;
	unsigned int server_w_enc_key_id;
	unsigned int client_w_mac_key_id;
	unsigned int server_w_mac_key_id;
	unsigned char *client_w_iv;
	unsigned int client_w_iv_length;
	unsigned char *server_w_iv;
	unsigned int server_w_iv_length;
};

/**
 * struct smw_kdf_tls12_random_data - TLS 1.2 random data
 * @version: [in] Version of this structure
 * @client_random: [in] Client generated random data buffer
 * @client_random_length: [in] @client_random length in bytes
 * @server_random: [in] Server generated random data buffer
 * @server_random_length: [in] @server_random length in bytes
 */
struct smw_kdf_tls12_random_data {
	unsigned char version;
	unsigned char *client_random;
	unsigned int client_random_length;
	unsigned char *server_random;
	unsigned int server_random_length;
};

/**
 * struct smw_kdf_tls12_session_hash - TLS 1.2 session hash
 * @version: [in] Version of this structure
 * @hash: [in] Hash of the session data
 * @hash_length: [in] @hash length in bytes
 */
struct smw_kdf_tls12_session_hash {
	unsigned char version;
	unsigned char *hash;
	unsigned int hash_length;
};

/**
 * struct smw_kdf_tls12_master_secret_args - TLS 1.2 master secret arguments
 * @version: [in] Version of this structure
 * @key_exchange_name: [in] Name of the key exchange algorithm
 *                     See &typedef smw_tls12_kea_t
 * @ext_master_key: [in] If true, generates an extended master secret key
 * @peer_public_buffer: [in] Peer public key used for ECDH(E)
 * @peer_public_buffer_length: [in] @peer_public_buffer length in bytes
 * @random_data: [in] The session random data, to be used when @ext_master_key is false
 * @session_hash: [in] The session hash, to be used when @ext_master_key is true
 *
 * This structure defines the additional arguments needed for the TLS 1.2
 * Master Secret. (&smw_derive_key_args->kdf_name = `TLS12_OP_KEY_EXCHANGE`).
 *
 * When @ext_master_key is true (Extended Master Secret - TLS1.2 extension, RFC 7627),
 * the @session_hash should be set appropriately. Otherwise, @random_data should be
 * filled in.
 */
struct smw_kdf_tls12_master_secret_args {
	unsigned char version;
	smw_tls12_kea_t key_exchange_name;
	bool ext_master_key;
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_length;
	union {
		struct smw_kdf_tls12_random_data *random_data;
		struct smw_kdf_tls12_session_hash *session_hash;
	};
};

/**
 * struct smw_kdf_tls12_key_expansion_args - TLS 1.2 key expansion arguments
 * @version: [in] Version of this structure
 * @encryption_name: [in] Name of the encryption algorithm
 *                   See &typedef smw_tls12_enc_t
 * @random_data: [in] The session random data
 * @client_w_enc_key_id: [out] Generated client write encryption key identifier
 * @server_w_enc_key_id: [out] Generated server write encryption key identifier
 * @client_w_mac_key_id: [out] Generated client write MAC key identifier (see note 1)
 * @server_w_mac_key_id: [out] Generated server write MAC key identifier (see note 1)
 * @client_w_iv: [in/out] Pointer to the Client IV buffer (see note 2)
 * @client_w_iv_length: [in/out] @client_w_iv length in bytes (see note 2)
 * @server_w_iv: [in/out] Pointer to the Server IV buffer (see note 2)
 * @server_w_iv_length: [in/out] @server_w_iv length in bytes (see note 2)
 *
 * This structure defines the additional arguments needed for the TLS 1.2
 * Key Expansion (&smw_derive_key_args->kdf_name = `TLS12_OP_KEY_EXCHANGE`).
 *
 * Note 1: Client/Server write MAC key are not generated with AEAD cipher
 *         encryption (CCM, GCM, CHACHA20_POLY1305).
 * Note 2: Client/Server write IVs are generated only in case of AEAD
 *         cipher modes (CCM, GCM, CHACHA20_POLY1305).
 */
struct smw_kdf_tls12_key_expansion_args {
	/* Inputs */
	unsigned char version;
	smw_tls12_enc_t encryption_name;
	struct smw_kdf_tls12_random_data *random_data;
	/* Outputs */
	unsigned int client_w_enc_key_id;
	unsigned int server_w_enc_key_id;
	unsigned int client_w_mac_key_id;
	unsigned int server_w_mac_key_id;
	unsigned char *client_w_iv;
	unsigned int client_w_iv_length;
	unsigned char *server_w_iv;
	unsigned int server_w_iv_length;
};

/**
 * struct smw_kdf_tls12_op_args - TLS 1.2 "operation-based" arguments
 * @version: [in] Version of this structure
 * @prf_name: [in] Name of the Pseudo-Random Function (PRF)
 *            See &typedef smw_hash_algo_t
 * @op_name: [in] Name of the operation to execute
 *            See &typedef smw_tls12_op_t
 * @context: [in] Pointer to an opaque operation context structure
 *           See &struct smw_op_context
 * @master_secret: [in] The TLS1.2 Master Secret parameters
 * @key_expansion: [in] The TLS1.2 Key Expansion parameters
 *
 * The @context passed through this structure must be a valid context which
 * is the result of the @smw_allocate_context function. Subsystems may allocate
 * data internally and associate it with the context. The same context needs to
 * be passed to the master secret and key expansion operations.
 *
 * Upon completion of the operations (with either success or error), the context
 * is not released and remains valid. Calling @smw_cancel_operation will release
 * it and any associated data.
 */
struct smw_kdf_tls12_op_args {
	unsigned char version;
	smw_hash_algo_t prf_name;
	smw_tls12_op_t op_name;
	struct smw_op_context *context;
	union {
		struct smw_kdf_tls12_master_secret_args master_secret;
		struct smw_kdf_tls12_key_expansion_args key_expansion;
	};
};

/**
 * struct smw_hkdf_args - HKDF full arguments structure
 * @salt: [in] Salt buffer
 * @salt_len: [in] @salt length in bytes
 * @info: [in] Context and application specific information buffer
 * @info_len: [in] @info length in bytes
 * @peer_public_buffer: [in] Peer public buffer
 * @peer_public_buffer_len: [in] @peer_public_buffer in bytes
 *
 * @info and @salt are optional parameters.
 * If @info and @salt are set, length of the respective buffers should be set.
 * @peer_public_buffer should be a valid public key and should be in hex format.
 */
struct smw_hkdf_args {
	unsigned char *salt;
	unsigned int salt_len;
	unsigned char *info;
	unsigned int info_len;
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_len;
};

/**
 * struct smw_hkdf_extract_args - HKDF extract step arguments structure
 * @salt: [in] Salt buffer
 * @salt_len: [in] @salt length in bytes
 * @peer_public_buffer: [in] Peer public buffer
 * @peer_public_buffer_len: [in] @peer_public_buffer in bytes
 *
 * @salt and @salt_len are optional parameters.
 *
 * @peer_public_buffer should be a valid public key and should be in hex format.
 *
 */
struct smw_hkdf_extract_args {
	unsigned char *salt;
	unsigned int salt_len;
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_len;
};

/**
 * struct smw_hkdf_expand_args - HKDF expand arguments structure
 * @info: [in] Context and application specific information
 * @info_len: [in] @info length in bytes
 *
 * @info and @info_len are optional parameters.
 */
struct smw_hkdf_expand_args {
	unsigned char *info;
	unsigned int info_len;
};

/**
 * struct smw_kdf_hkdf_args - HMAC-based Key derivation function arguments
 * @extract: [in] Execute the extract step of HKDF
 * @expand: [in] Execute the expand step of HKDF
 * @hash_algo: [in] Hash algorithm name. See &typedef smw_hash_algo_t
 * @hkdf_args: [in/out] HKDF full arguments. See &struct smw_hkdf_args
 * @hkdf_extract_args: [in/out] HKDF extract step arguments.
 *						See &struct hkdf_extract_args
 * @hkdf_expand_args: [in] HKDF expand step arguments.
 *						See &struct hkdf_expand_args
 *
 * If user requests to store the derived key, user must provide
 * @smw_derive_key_args.key_descriptor_derived.type_name,
 * @smw_derive_key_args.key_descriptor_derived.security_size,
 * @smw_derive_key_args.key_attributes.usage_flags,
 * @smw_derive_key_args.key_attributes.attributes and, if required by
 * the subsystem, the @smw_derive_key_args.key_attributes.permitted_algo.
 *
 * Key derivation using HKDF can be performed either in two dedicated steps
 * (extract and expand) or combined into a single step, but only if the
 * subsystem supports this capability.
 *
 *  - Step #1: Extract
 *
 *    - @smw_derive_key_args.store_derived_key is ignored. Upon successful
 *      completion of this step, PRK buffer is exported if
 *      @smw_derive_key_args.key_descriptor_derived.shared_secret and
 *      @hkdf_extract_args.prk_len are set or PRK ID
 *      @smw_derive_key_args.key_descriptor_derived.id is set.
 *    - PRK is temporarily stored in subsystem key storage. It’s deleted when
 *      the key derivation operation is completed.
 *    - If base key is a plaintext buffer, the base key type should be set to
 *      SMW_KEY_TYPE_NAME_RAW.
 *
 *  - Step #2: Expand
 *
 *    - If PRK ID @smw_derive_key_args.key_descriptor_base.id is set, PRK
 *      buffer @smw_derive_key_args.key_descriptor_base.buffer->gen.public_data
 *      is ignored. If PRK buffer is exported, the base key type should be set
 *      to SMW_KEY_TYPE_NAME_RAW.
 *    - Upon successful completion of the key derivation operation, derived key
 *      descriptor structure @smw_derive_key_args.key_descriptor_derived is
 *      updated. The new key ID is set and shared secret data is exported if
 *      shared_secret and shared_secret_len are set in the derived key
 *      descriptor structure @smw_derive_key_args.key_descriptor_derived.
 *
 *  - Full HKDF (step 1 and step 2 combined)
 *
 *    - Upon successful completion of the key derivation operation, derived key
 *      descriptor structure @smw_derive_key_args.key_descriptor_derived is
 *      updated. The new derived key ID is set, and shared secret data is
 *      exported if shared_secret and shared_secret_len are set in the derived
 *      key descriptor structure @smw_derive_key_args.key_descriptor_derived.
 *    - If base key is a plaintext buffer, the base key type should be set to
 *      SMW_KEY_TYPE_NAME_RAW.
 */
struct smw_kdf_hkdf_args {
	bool extract;
	bool expand;
	smw_hash_algo_t hash_algo;
	union {
		struct smw_hkdf_args hkdf_args;
		struct smw_hkdf_extract_args hkdf_extract_args;
		struct smw_hkdf_expand_args hkdf_expand_args;
	};
};

/**
 * struct smw_kdf_ecdh_args - Key derivation function ECDH arguments
 * @peer_public_buffer: Key derivation input data used to generate the shared
 * secret key
 * @peer_public_buffer_length: Length in bytes of the @peer_public_buffer buffer
 *
 * This structure defines the additional arguments needed for the ECDH
 * Key derivation (&smw_derive_key_args->kdf_name = `ECDH`).
 *
 * Upon successful completion of the key derivation operation, derived key
 * descriptor structure @smw_derive_key_args.key_descriptor_derived is
 * updated. The new derived key ID is set, and shared secret data is
 * exported if shared_secret and shared_secret_len are set in the derived
 * key descriptor structure @smw_derive_key_args.key_descriptor_derived.
 */
struct smw_kdf_ecdh_args {
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_length;
};

/**
 * struct smw_update_key_args - Key update arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 */
struct smw_update_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	//TODO: define smw_update_key_args
};

/**
 * struct smw_import_key_args - Key import arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_attributes: Pointer to a Key attributes object. See &smw_key_attributes
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * The @key_descriptor fields @type_name and @security_size must be given
 * as input to define the type of key to import.
 * The @key_descriptor field @buffer is mandatory. A public key, a private key
 * or a key pair is imported if the corresponding pointer and size is set.
 * The @key_descriptor field @id, if set by the caller (other than 0) will be
 * the created key identifier on operation success. Else the API will returned
 * a new key identifier if @id is set as 0.
 * The @buffer field @format_name is optional. The default value is "HEX".
 */
struct smw_import_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_attributes *key_attributes;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_export_key_args - Key export arguments
 * @version: Version of this structure
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * The @key_descriptor fields @id must be given as input.
 * The @key_descriptor field @buffer is mandatory.
 * The public key buffer must be set in order to export the public Key,
 * in case of asymmetric Keys.
 * The private key buffer must be set in order to export the private Key,
 * only if the Secure Subsystem supports it. In that case, the private Key
 * may be encrypted, not plaintext.
 * The user can use smw_get_key_buffers_lengths() to set correct lengths
 * for the public/private key buffer(s).
 */
struct smw_export_key_args {
	unsigned char version;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_delete_key_args - Key deletion arguments
 * @version: Version of this structure (must be equal 1).
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * The @key_descriptor fields @id must be given as input.
 * The @key_descriptor fields @buffer is ignored.
 */
struct smw_delete_key_args {
	unsigned char version;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_get_key_attributes_args - Get key attributes arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 * @key_privacy_name: Key privacy name
 * @key_attributes: Key attributes. See &smw_key_attributes
 *
 * The @key_descriptor fields @id must be given as input.
 * The @key_descriptor fields @buffer is ignored.
 * The @key_descriptor fields @type_name and @security_size are output.
 */
struct smw_get_key_attributes_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_key_privacy_t key_privacy_name;
	struct smw_key_attributes key_attributes;
};

/**
 * struct smw_commit_key_storage_args - Commit non-volatile key storage arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 */
struct smw_commit_key_storage_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
};

/**
 * struct smw_key_attestation_args - Device attestation arguments
 * @version: Version of this structure
 * @key_descriptor: Pointer to a Key descriptor object of the key to be attested.
 *		    See &struct smw_key_descriptor
 * @attest_key_descriptor: Pointer to a Key descriptor object
 *			   of the attestation key.
 *			   See &struct smw_key_descriptor
 * @sign_algo: Signature algorithm and attributes. See &typedef smw_attr_algo_t
 * @challenge: Caller unique ephemeral value (e.g. nonce)
 * @challenge_length: Length (in bytes) of the @challenge value
 * @certificate: Device attestation certificate.
 * @certificate_length: Length (in bytes) of the @certificate.
 *
 * @challenge length depends on the key (refer to the subsystem capabilities).
 * If the length is bigger than expected, it will be cut to keep only the
 * maximum size. If the length is shorter, the challenge value will be completed
 * with 0's.
 */
struct smw_key_attestation_args {
	unsigned char version;
	struct smw_key_descriptor *key_descriptor;
	struct smw_key_descriptor *attest_key_descriptor;
	smw_attr_algo_t sign_algo;
	unsigned char *challenge;
	unsigned int challenge_length;
	unsigned char *certificate;
	unsigned int certificate_length;
};

/**
 * smw_generate_key() - Generate a Key.
 * @args: Pointer to the structure that contains the Key generation arguments.
 *
 * This function generates a Key.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_generate_key(struct smw_generate_key_args *args);

/**
 * smw_derive_key() - Derive a Key.
 * @args: Pointer to the structure that contains the Key derivation arguments.
 *
 * This function derives a Key.
 *
 * If the shared secret length @args->key_descriptor_derived->shared_secret_len
 * is shorter than expected, this function returns status code
 * SMW_STATUS_OUTPUT_TOO_SHORT and updates the shared secret length to the
 * correct value.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_derive_key(struct smw_derive_key_args *args);

/**
 * smw_update_key() - Update a Key.
 * @args: Pointer to the structure that contains the Key update arguments.
 *
 * This function updates the Key attribute list.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_update_key(struct smw_update_key_args *args);

/**
 * smw_import_key() - Import a Key.
 * @args: Pointer to the structure that contains the Key import arguments.
 *
 * This function imports a Key into the storage managed by the Secure Subsystem.
 * The key must be plain text.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_import_key(struct smw_import_key_args *args);

/**
 * smw_export_key() - Export a Key.
 * @args: Pointer to the structure that contains the Key export arguments.
 *
 * This function exports a Key.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_export_key(struct smw_export_key_args *args);

/**
 * smw_delete_key() - Delete a Key.
 * @args: Pointer to the structure that contains the Key deletion arguments.
 *
 * This function deletes a Key.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_delete_key(struct smw_delete_key_args *args);

/**
 * smw_get_key_buffers_lengths() - Gets Key buffers lengths.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function calculates either:
 *  - The subsystem key buffers' lengths of the given @descriptor
 *    field @id. Only the exportable buffer lengths are returned.
 *  - The standard key buffers's lengths of the given @descriptor
 *    fields @type_name, @security_size.
 *
 * The @descriptor field @buffer is mandatory.
 * The @buffer field @format_name is optional.
 * The @buffer fields @public_length, @modulus and @private_length are updated.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor);

/**
 * smw_get_key_type_name() - Gets the Key type name.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function gets the Key type name given the Key ID.
 * The @descriptor field @id must be given as input.
 * The @descriptor fields @type_name is updated.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_get_key_type_name(struct smw_key_descriptor *descriptor);

/**
 * smw_get_security_size() - Gets the Security size.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function gets the Security size given the Key ID.
 * The @descriptor field @id must be given as input.
 * The @descriptor fields @security_size is updated.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_get_security_size(struct smw_key_descriptor *descriptor);

/**
 * smw_get_key_attributes() - Get the key attributes.
 * @args: Pointer to the structure that contains the Key attributes arguments.
 *
 * This function gets the Key attributes retrieved for the subsystem owning the
 * given key identifier.
 * If some key attributes are not supported, the output values are empty.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_get_key_attributes(struct smw_get_key_attributes_args *args);

/**
 * smw_commit_key_storage() - Commit the active non-volatile key storage
 * @args: Pointer to the structure that contains the commit storage arguments.
 *
 * This function ensures that the non-volatile key storage opened by the
 * subsystem is pushed in physical memory and associated anti-rollback
 * protection counter is incremented.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_commit_key_storage(struct smw_commit_key_storage_args *args);

/**
 * smw_key_attestation() - Get the key attestation certificate.
 * @args: Pointer to the structure that contains the key attestation arguments.
 *
 * Reads the key attestation certificate.
 *
 * Certificate length of @args field is updated to the correct value when:
 *  - Length is bigger than expected. In this case operation succeeded.
 *  - Length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *  - Certificate buffer is set the NULL. In this case operation returned
 *    SMW_STATUS_OK
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_key_attestation(struct smw_key_attestation_args *args);

#endif /* __SMW_KEYMGR_H__ */
