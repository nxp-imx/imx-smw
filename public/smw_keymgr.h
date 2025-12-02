/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SMW_KEYMGR_H__
#define __SMW_KEYMGR_H__

#include <stdbool.h>

#include "smw_status.h"
#include "smw/attr.h"
#include "smw/names.h"
#include "smw/kdf/tls.h"
#include "smw/kdf/oem_master_key.h"

/**
 * struct smw_keypair_gen - Generic Keypair object
 * @public_data: [in/out] Pointer to the public key buffer.
 * @public_length: [in/out] Length in bytes of the public key buffer.
 * @private_data: [in/out] Pointer to the private key buffer.
 * @private_length: [in/out] Length in bytes of the private key buffer.
 *
 * Generic asymmetric keypair structure used for ECC and Edwards curves.
 */
struct smw_keypair_gen {
	unsigned char *public_data;
	unsigned int public_length;
	unsigned char *private_data;
	unsigned int private_length;
};

/**
 * struct smw_keypair_rsa - RSA Keypair object
 * @public_data: [in/out] Pointer to the RSA public exponent buffer.
 * @public_length: [in/out] Length in bytes of the RSA public exponent buffer.
 * @private_data: [in/out] Pointer to the RSA private exponent buffer.
 * @private_length: [in/out] Length in bytes of the RSA private exponent buffer.
 * @modulus: [in/out] Pointer to the RSA modulus buffer.
 * @modulus_length: [in/out] Length in bytes of the RSA modulus buffer.
 * @public_exponent: [in] Pointer to the RSA public exponent buffer
 *                   (key creation only).
 * @public_exponent_length: [in/out] Length in bytes of the RSA public exponent
 *                          buffer.
 *
 * Asymmetric keypair structure used for RSA key operations.
 *
 * First fields are common to the struct smw_keypair_gen and must be
 * kept common.
 *
 * Input parameters @public_exponent and @public_exponent_length are only
 * used for key generation. For other operations, they are ignored, and
 * @public_data and @public_length must be set instead.
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
 * @format_name: [in] Defines the encoding format of all buffers.
 *               See &typedef smw_key_format_t
 * @gen: Generic keypair object definition. See &struct smw_keypair_gen
 * @rsa: RSA keypair object definition. See &struct smw_keypair_rsa
 *
 * By default if format name is not specified, it's equivalent to "HEX" format.
 */
struct smw_keypair_buffer {
	smw_key_format_t format_name;
	union {
		struct smw_keypair_gen gen;
		struct smw_keypair_rsa rsa;
	};
};

/**
 * struct smw_key_attributes - Key attributes
 * @permitted_algo: [in/out] Permitted algorithm. See &typedef smw_attr_algo_t
 * @usage_flags: [in/out] Permitted usage flags. See &typedef smw_attr_usage_t
 * @storage_id: [in/out] Storage identifier. See &typedef smw_attr_storage_id_t
 * @attributes: [in/out] Attributes. See &typedef smw_attr_attributes_t
 *
 * Definition of the key attributes members are not all used. It may
 * be function of the subsystem.
 * In case of key creation, it's recommended to define all members correctly
 * even if not used.
 */
struct smw_key_attributes {
	smw_attr_algo_t permitted_algo;
	smw_attr_usage_t usage_flags;
	smw_attr_storage_id_t storage_id;
	smw_attr_attributes_t attributes;
};

/**
 * struct smw_key_descriptor - Key descriptor
 * @type_name: [in/out] Key type name. See &typedef smw_key_type_t
 * @security_size: [in/out] Security size in bits.
 * @id: [in/out] Key identifier.
 * @attributes: [in/out] Key attributes. see &struct smw_key_attributes
 * @buffer: [in/out] Pointer to key pair buffer. See &struct smw_keypair_buffer
 *
 * The @attributes definition is not used by all APIs. It's documented
 * in API's argument when this field is used.
 *
 * The @buffer is optional and may depend on the key operation.
 */
struct smw_key_descriptor {
	smw_key_type_t type_name;
	unsigned int security_size;
	unsigned int id;
	struct smw_key_attributes attributes;
	struct smw_keypair_buffer *buffer;
};

/**
 * struct smw_derived_key_descriptor - Derived key descriptor structure
 * @type_name: [in] Key type name. See &typedef smw_key_type_t
 * @security_size: [in] Security size in bits.
 * @id: [in/out] Key identifier.
 * @attributes: Key attributes. see &struct smw_key_attributes
 * @format_name: [in] Defines the encoding format of shared secret buffer.
 *               See &typedef smw_key_format_t
 * @shared_secret: [in/out] Pointer to shared secret buffer.
 * @shared_secret_len: [in/out] Length in bytes of the shared secret buffer.
 */
struct smw_derived_key_descriptor {
	smw_key_type_t type_name;
	unsigned int security_size;
	unsigned int id;
	struct smw_key_attributes attributes;
	smw_key_format_t format_name;
	unsigned char *shared_secret;
	unsigned int shared_secret_len;
};

/**
 * struct smw_generate_key_args - Key generation arguments
 * @version: [in] Version of this structure
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_descriptor: Pointer to a Key descriptor object.
 *                  See &struct smw_key_descriptor
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 *
 * The @key_descriptor fields:\
 *
 *  - @id: [in] key identifier:\
 *
 *    - if set to 0, the API will return a new key identifier.
 *    - if set by the caller (other than 0) subsystem will create a key with
 *      user defined key identifier. If key identifier already exists,
 *      operation fails.
 *      By principle, the user defined key identifier must not be set when
 *      transient key is created. Some subsystems may not support user defined
 *      key identifiers for transient keys.
 *
 *  - @type_name: [in] Key type name. See &typedef smw_key_type_t
 *  - @security_size: [in] Security size in bits.
 *  - @attributes: Key attributes. See &struct smw_key_attributes.\
 *
 *                 - [in] key attributes to set.
 *                 - [out] key attributes effectively set by the subsystem.
 *
 *
 *  - @buffer: [in/out] **Optional**, used to export the asymmetric public key
 *    generated. The buffer array and size must be set to contain the
 *    public key value. If buffer is too small, operation returns with
 *    SMW_STATUS_OUTPUT_TOO_SHORT updating the expected buffer size.
 *    Key is not created.
 *
 */
struct smw_generate_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_derive_key_args - Key derivation arguments
 * @version: [in] Version of this structure
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t
 * @kdf_name: [in] Key derivation function name. See &typedef smw_kdf_t
 * @kdf_arguments: [in] Key derivation function arguments
 * @store_derived_key: [in] If true, store the derived key.
 * @key_descriptor_base: [in] Pointer to a Key base descriptor.
 *                       See &struct smw_key_descriptor
 * @key_descriptor_derived: [in/out] Pointer to the Key derived descriptor
 *                          structure. See &struct smw_derived_key_descriptor
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 *
 * A new key is derived from a given key base (@key_descriptor_base) using
 * the key derivation function @kdf_name.
 * If the key derivation function requires more arguments,
 * the @kdf_arguments refers to the associated key derivation function
 * arguments, else this pointer is not used and can be NULL.
 *
 * Upon successful completion of the key derivation operation, if
 * @store_derived_key is set to true, a new key ID
 * is set in the @key_descriptor_derived->id.
 * The shared secret data is exported if @key_descriptor_derived->shared_secret
 * and @key_descriptor_derived->shared_secret_len are set.
 * Refer to the :ref:`subsystems-capabilities` for more details.
 *
 * The @key_descriptor_derived.attributes must be defined.
 */
struct smw_derive_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_kdf_t kdf_name;
	void *kdf_arguments;
	bool store_derived_key;
	struct smw_key_descriptor *key_descriptor_base;
	struct smw_derived_key_descriptor *key_descriptor_derived;
};

/**
 * struct smw_kdf_tls12_args - Key derivation function TLS 1.2 arguments
 * @key_exchange_name: [in] Name of the key exchange algorithm.
 *                     See &typedef smw_tls12_kea_t
 * @encryption_name: [in] Name of the encryption algorithm.
 *                   See &typedef smw_tls12_enc_t
 * @prf_name: [in] Name of the Pseudo-Random Function (PRF).
 *            See &typedef smw_hash_algo_t
 * @ext_master_key: [in] If true, generates an extended master secret key.
 * @kdf_input: [in] Pointer to the key derivation input data buffer
 *             used to generate the master secret key.
 * @kdf_input_length: [in] Length in bytes of the key derivation input data
 *                    buffer.
 * @master_sec_key_id: [out] Generated master key identifier.
 * @client_w_enc_key_id: [out] Generated client write encryption key identifier.
 * @server_w_enc_key_id: [out] Generated server write encryption key identifier.
 * @client_w_mac_key_id: [out] Generated client write MAC key identifier (see note 1).
 * @server_w_mac_key_id: [out] Generated server write MAC key identifier (see note 1).
 * @client_w_iv: [out] Pointer to the Client IV buffer (see note 2).
 * @client_w_iv_length: [in/out] Length in bytes of the Client IV buffer.
 * @server_w_iv: [out] Pointer to the Server IV buffer (see note 2).
 * @server_w_iv_length: [in/out] Length  in bytes of the Server IV buffer.
 *
 * This structure defines the additional arguments needed for the TLS 1.2
 * Key derivation when:\
 *
 *  - &smw_derive_key_args->kdf_name = :ref:`SMW_KDF_NAME_TLS12_KEY_EXCHANGE <smw_kdf_t>`
 *
 * .. note::
 *
 *   1. Client/Server write MAC key are not generated with AES GCM cipher
 *      encryption.
 *   2. Client/Server write IVs are generated only in case of Authentication
 *      Encryption with Additional Data Cipher mode (like AES CCM or GCM).
 *
 * The key derivation &smw_derive_key_args->key_descriptor_derived is filled
 * only if the @key_exchange_name request for an ephemeral public key.
 *
 * Following &smw_derive_key_args->key_descriptor_derived fields are:\
 *
 *  - @id: set to 0
 *  - @type_name: Set the key type name
 *  - @security_size: Size in bits of the derived key
 *  - @shared_secret: Shared secret buffer
 *  - @shared_secret_len: Shared secret buffer length
 *
 * .. warning::
 *	This structure is deprecated and will be removed in a future library
 *	release. Please use the new structure `smw_kdf_tls12_op_args`_ instead.
 */
struct smw_kdf_tls12_args {
	smw_tls12_kea_t key_exchange_name;
	smw_tls12_enc_t encryption_name;
	smw_hash_algo_t prf_name;
	bool ext_master_key;
	unsigned char *kdf_input;
	unsigned int kdf_input_length;
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
 * @version: [in] Version of this structure.
 * @client_random: [in] Pointer to Client random data buffer.
 * @client_random_length: [in] Length in bytes of the Client random data buffer.
 * @server_random: [in] Pointer to Server random data buffer.
 * @server_random_length: [in] Length in bytes of the Server random data buffer.
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
 * @version: [in] Version of this structure.
 * @hash: [in] Pointer to the hash buffer of the session data.
 * @hash_length: [in] Length in bytes of the hash buffer.
 */
struct smw_kdf_tls12_session_hash {
	unsigned char version;
	unsigned char *hash;
	unsigned int hash_length;
};

/**
 * struct smw_kdf_tls12_master_secret_args - TLS 1.2 master secret arguments
 * @version: [in] Version of this structure.
 * @key_exchange_name: [in] Name of the key exchange algorithm.
 *                     See &typedef smw_tls12_kea_t
 * @ext_master_key: [in] If true, generates an extended master secret key.
 * @peer_public_buffer: [in] Pointer to the Peer public key buffer used for ECDH(E).
 * @peer_public_buffer_length: [in] Length in bytes of the Perr public key buffer.
 * @random_data: [in] If @ext_master_key is `false`, definition of the session
 *               random data (`smw_kdf_tls12_random_data`_).
 * @session_hash: [in] If @ext_master_key is `true`, definition of the session hash
 *                (`smw_kdf_tls12_session_hash`_).
 *
 * This structure defines the additional arguments needed for the TLS 1.2
 * Master Secret, when:\
 *
 *   - &smw_derive_key_args->kdf_name =
 *     :ref:`SMW_KDF_NAME_TLS12_OP_KEY_EXCHANGE <smw_kdf_t>`
 *   - &smw_derive_key_args->kdf_arguments is a type &smw_kdf_tls12_op_args
 *     where &smw_kdf_tls12_op_args->op_name =
 *     :ref:`SMW_TLS12_OP_NAME_MASTER_SECRET <smw_tls12_op_t>`.
 *
 *
 * .. note::
 *    As detailed in the `Extended Master Secret - TLS1.2 extension, RFC 7627
 *    <https://www.rfc-editor.org/rfc/rfc7627>`_:\
 *
 *    - when **ext_master_key** is **true**, the **session_hash** should be set.
 *    - when **ext_master_key** is **false**, the **random_data** should be set.
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
 * @version: [in] Version of this structure.
 * @encryption_name: [in] Name of the encryption algorithm.
 *                   See &typedef smw_tls12_enc_t
 * @random_data: [in] The session random data.
 * @client_w_enc_key_id: [out] Generated client write encryption key identifier.
 * @server_w_enc_key_id: [out] Generated server write encryption key identifier.
 * @client_w_mac_key_id: [out] Generated client write MAC key identifier (see note 1).
 * @server_w_mac_key_id: [out] Generated server write MAC key identifier (see note 1).
 * @client_w_iv: [in/out] Pointer to the Client IV buffer (see note 2).
 * @client_w_iv_length: [in/out] Length in bytes of the Client IV buffer.
 * @server_w_iv: [in/out] Pointer to the Server IV buffer (see note 2).
 * @server_w_iv_length: [in/out] Length in bytes of the Server IV buffer.
 *
 * This structure defines the additional arguments needed for the TLS 1.2
 * Key Expansion, when:\
 *
 *   - &smw_derive_key_args->kdf_name =
 *     :ref:`SMW_KDF_NAME_TLS12_OP_KEY_EXCHANGE <smw_kdf_t>`
 *   - &smw_derive_key_args->kdf_arguments is a type &smw_kdf_tls12_op_args
 *     where &smw_kdf_tls12_op_args->op_name =
 *     :ref:`SMW_TLS12_OP_NAME_KEY_EXPANSION <smw_tls12_op_t>`.
 *
 * .. note::
 *
 *   1. Client/Server write MAC key are not generated with AEAD cipher
 *      encryption (CCM, GCM, CHACHA20_POLY1305).
 *   2. Client/Server write IVs are generated only in case of AEAD
 *      cipher modes (CCM, GCM, CHACHA20_POLY1305).
 */
struct smw_kdf_tls12_key_expansion_args {
	unsigned char version;
	smw_tls12_enc_t encryption_name;
	struct smw_kdf_tls12_random_data *random_data;
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
 * @version: [in] Version of this structure.
 * @prf_name: [in] Name of the Pseudo-Random Function (PRF).
 *            See &typedef smw_hash_algo_t
 * @op_name: [in] Name of the operation to execute.
 *            See &typedef smw_tls12_op_t
 * @context: [in] Pointer to an opaque operation context structure.
 *           See &struct smw_op_context
 * @master_secret: [in] The TLS1.2 Master Secret parameters.
 * @key_expansion: [in] The TLS1.2 Key Expansion parameters.
 *
 * The @context passed through this structure must be a valid context which
 * is the result of the smw_allocate_context() function. Subsystems may allocate
 * data internally and associate it with the context. The same context needs to
 * be passed to the master secret and key expansion operations.
 *
 * Upon completion of the operations (with either success or error), the context
 * is not released and remains valid. Calling smw_cancel_operation() will release
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
 * struct smw_kdf_tls13_args - TLS1.3 KDF arguments structure
 * @version: [in] Version of this structure.
 * @psk: [in, optional] The Pre-Shared Key to use for Early Secret derivation.
 *       See &struct smw_key_descriptor
 * @prf_name: [in] Name of the Pseudo-Random Function (PRF).
 *            See &typedef smw_hash_algo_t
 * @peer_public_buffer: [in] Pointer to the Peer public buffer.
 * @peer_public_buffer_length: [in] Length in bytes of the Peer public buffer.
 * @expanded_label: [in] Pointer to the expanded label buffer.
 * @expanded_label_length: [in] Length in bytes of the expanded label buffer.
 *
 * The @expand_label must be a buffer that contains the output of TLS1.3's
 * "HKDF-Expand_label". The smw_tls13_expand_label() is a helper function you may
 * use to compute the expanded label, from the input label and context data
 * (the context is usually the Transcript Hash).
 *
 * The value of the input label controls which actual secrets get derived,
 * e.g.:\
 *
 *  - "ext binder" -> binder_key
 *  - "c hs traffic" -> client_handshake_traffic_secret
 *  - "c ap traffic" -> client_application_traffic_secret_0
 *
 * Please refer to `RFC 8446 <https://www.rfc-editor.org/rfc/rfc8446>`_,
 * `section 7.1 <https://www.rfc-editor.org/rfc/rfc8446#section-7.1>`_,
 * to see the possible values for the label.
 */
struct smw_kdf_tls13_args {
	unsigned char version;
	struct smw_key_descriptor *psk;
	smw_hash_algo_t prf_name;
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_length;
	unsigned char *expanded_label;
	unsigned int expanded_label_length;
};

/**
 * struct smw_hkdf_extract_args - HKDF extract step arguments structure
 * @salt: [in] (opional) Pointer to the Salt buffer.
 * @salt_len: [in] Length in bytes of the Salt buffer.
 * @peer_public_buffer: [in] Pointer to the Peer public buffer in hex format.
 * @peer_public_buffer_len: [in] Length in bytes of the Peer public buffer.
 *
 * Refer to `RFC5869 section 2.2 <https://www.rfc-editor.org/rfc/rfc5869#section-2.2>`_
 */
struct smw_hkdf_extract_args {
	unsigned char *salt;
	unsigned int salt_len;
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_len;
};

/**
 * struct smw_hkdf_expand_args - HKDF expand arguments structure
 * @info: [in] (optional) Context and application specific information buffer.
 * @info_len: [in] Length in bytes of context and application specitic
 *            information buffer.
 *
 * Refer to `RFC5869 section 2.3 <https://www.rfc-editor.org/rfc/rfc5869#section-2.3>`_
 */
struct smw_hkdf_expand_args {
	unsigned char *info;
	unsigned int info_len;
};

/**
 * struct smw_hkdf_args - HKDF full arguments structure
 * @extract_args: [in] HKDF extract arguments structure.
 *                See &struct hkdf_extract_args
 * @expand_args: [in] HKDF expand arguments structure.
 *               See &struct hkdf_expand_args
 *
 * This structure is used to operate a 2-steps HKDF key derivation that are
 * extract and expand.
 */
struct smw_hkdf_args {
	struct smw_hkdf_extract_args extract_args;
	struct smw_hkdf_expand_args expand_args;
};

/**
 * struct smw_kdf_hkdf_args - HMAC-based Key derivation function arguments
 * @hash_algo: [in] Hash algorithm name. See &typedef smw_hash_algo_t
 * @hkdf_args: [in/out] HKDF full arguments. See &struct smw_hkdf_args
 * @hkdf_extract_args: [in/out] HKDF extract step arguments.
 *                     See &struct hkdf_extract_args
 * @hkdf_expand_args: [in] HKDF expand step arguments.
 *                    See &struct hkdf_expand_args
 *
 * This structure defines the additional arguments needed for the HKDF
 * derivation when:\
 *
 *  - &smw_derive_key_args->kdf_name = :ref:`SMW_KDF_NAME_HKDF <smw_kdf_t>`
 *  - &smw_derive_key_args->kdf_name = :ref:`SMW_KDF_NAME_HKDF_EXTRACT <smw_kdf_t>`
 *  - &smw_derive_key_args->kdf_name = :ref:`SMW_KDF_NAME_HKDF_EXPAND <smw_kdf_t>`
 *
 * If user requests to store the derived key, user must provide:\
 *
 *   - &smw_derive_key_args.key_descriptor_derived.type_name
 *   - &smw_derive_key_args.key_descriptor_derived.security_size
 *   - &smw_derive_key_args.key_attributes.usage_flags
 *   - &smw_derive_key_args.key_attributes.attributes
 *   - &smw_derive_key_args.key_attributes.permitted_algo
 *
 * The `RFC5869 <https://www.rfc-editor.org/rfc/rfc5869>`_ details the
 * HMAC-based Key derivation function (HKDF).
 *
 * Key derivation using HKDF can be performed either in two dedicated steps
 * (extract and expand) or combined into a single step, but only if the
 * subsystem supports this capability.
 *
 *  - Step #1: Extract (Standalone operation not yet supported)
 *
 *    - Upon successful completion of this step, resulting pseudorandom
 *      key buffer (PRK) is exported if the key derivation
 *      &smw_derive_key_args.key_descriptor_derived Shared Secret buffer is
 *      defined.
 *      Otherwise a subsystem key is created and the
 *      &smw_derive_key_args.key_descriptor_derived key identifier set with
 *      the new created key identifier.
 *
 *  - Step #2: Expand (Standalone operation not yet supported)
 *
 *    - Upon successful completion of the key derivation operation, derived key
 *      descriptor structure &smw_derive_key_args.key_descriptor_derived is
 *      updated. The new key ID is set and shared secret data is exported if
 *      &smw_derive_key_args.key_descriptor_derived.shared_secret defined.
 *
 *  - Full HKDF (step 1 and step 2 combined)
 *
 *    - Upon successful completion of the key derivation operation, derived key
 *      descriptor structure &smw_derive_key_args.key_descriptor_derived is
 *      updated. The new derived key ID is set, and shared secret data is
 *      exported if buffer defined.
 *
 *  For the three types of operation supported, the input key material is either
 *  a key identifier or a raw buffer. The &smw_derive_key_args.key_descriptor_base
 *  define how the input material IKM (in case of extract or full operation)
 *  or PRK (in case of expand operation) is given:\
 *
 *    - It's a key identifier, the base key identifier set.
 *    - It's a raw buffer, the base key descriptor's generic key keypair's
 *      Public data buffer contains the raw value and the key type name is set
 *      to :ref:`SMW_KEY_TYPE_NAME_RAW <smw_key_type_t>`.
 */
struct smw_kdf_hkdf_args {
	smw_hash_algo_t hash_algo;
	union {
		struct smw_hkdf_args hkdf_args;
		struct smw_hkdf_extract_args hkdf_extract_args;
		struct smw_hkdf_expand_args hkdf_expand_args;
	};
};

/**
 * struct smw_kdf_ecdh_args - Key derivation function ECDH arguments
 * @peer_public_buffer: [in] Pointer to the Peer public key buffer in hex format.
 * @peer_public_buffer_length: [in] Length in bytes of the Peer public key buffer.
 *
 * This structure defines the additional arguments needed for the ECDH
 * Key derivation when:\
 *
 *  - &smw_derive_key_args->kdf_name = :ref:`SMW_KDF_NAME_ECDH <smw_kdf_t>`
 *
 * Upon successful completion of the key derivation operation, derived key
 * descriptor structure &smw_derive_key_args.key_descriptor_derived is
 * updated. The new derived key ID is set, and shared secret data is
 * exported if Shared Secret buffer is defined.
 */
struct smw_kdf_ecdh_args {
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_length;
};

/**
 * struct smw_import_key_args - Key import arguments
 * @version: [in] Version of this structure
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_descriptor: [in/out] Pointer to a Key descriptor object.
 *                  See &struct smw_key_descriptor
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 *
 * The @key_descriptor fields:\
 *
 *  - @id: [in] key identifier:\
 *
 *    - if set to 0, the API will return a new key identifier.
 *    - if set by the caller (other than 0) subsystem will create a key with
 *      user defined key identifier. If key identifier already exists,
 *      operation fails.
 *      By principe, the user defined key identifier must not be set when
 *      transient key is created. Some subsystems may not support user defined
 *      key identifiers for transient keys.
 *
 *  - @type_name: [in] Key type name. See &typedef smw_key_type_t
 *  - @security_size: [in] Security size in bits.
 *  - @attributes: Key attributes. See &struct smw_key_attributes.\
 *
 *                 - [in] key attributes to set.
 *                 - [out] key attributes effectively set by the subsystem.
 *
 *
 *  - @buffer: [in/out] define the key value to import. Function of the
 *    subsystem, importable key can be:\
 *
 *      - Symmetric key private key buffer contains the key value.
 *      - ECC or Edwards asymmetric public key: public key buffer contains the
 *        key value.
 *      - ECC or Edwards asymmetric keypair: public and pivate key buffer
 *        contains the key value.
 *      - RSA asymmetric public key: public and modulus key buffers contains
 *        the key value.
 *      - RSA asymmetric keypair: public, private and modulus key buffers
 *        contains the key value.
 *
 * The @buffer field @format_name is optional. The default value is "HEX".
 *
 * Secure subsystem may accept or not to import a private or secure key buffer
 * plaintext value.
 *
 * Secure subsystem may only accept to import a private or secure key buffer
 * encoded in a specific format conveying the encrypted value of the key.
 * The @key_descriptor->attributes.storage_id must be set according to the
 * key encoding format.
 */
struct smw_import_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_export_key_args - Key export arguments
 * @version: [in] Version of this structure
 * @key_descriptor: [in/out] Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * The @key_descriptor fields:\
 *
 *  - @id: [in] Key identifier. Identifier returned during the key creation
 *    smw_generate_key() or smw_import_key().
 *  - @type_name: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with
 *    SMW_KEY_TYPE_NAME_NONE.
 *  - @security_size: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with 0.
 *  - @attributes: [in] If key is present in the SMW's database, it's ignored.
 *    Otherwise, only key's persistency is considered.
 *  - @buffer: [out] Define the key value to export as follow:\
 *
 *    - For ECC or Edwards asymmetric key:\
 *
 *      - The public key buffer must be set in order to export the public key.
 *      - The private key buffer must be set in order to export the private key,
 *        only if the Secure Subsystem supports it. In that case, the private
 *        key may be encrypted, not plaintext.
 *
 *    - For RSA asymmetric key:\
 *
 *      - The public key buffer must be set in order to export the public key.
 *      - The modulus buffer must be set in order to export the key's modulus.
 *      - The private key buffer must be set in order to export the private key,
 *        only if the Secure Subsystem supports it. In that case, the private
 *        key may be encrypted, not plaintext.
 *
 *    - For symmetric key:\
 *
 *      - The private key buffer must be set in order to export the secure key,
 *        only if the Secure Subsystem supports it. In that case, the secure key
 *        may be encrypted, not plaintext.
 *
 *
 *
 * The user can use smw_get_key_buffers_lengths() to get the public and/or
 * private key buffer(s) lengths, to allocate corresponding exported buffers.
 */
struct smw_export_key_args {
	unsigned char version;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_delete_key_args - Key deletion arguments
 * @version: [in] Version of this structure (must be equal 1).
 * @key_descriptor: [in] Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * The @key_descriptor fields:\
 *
 *  - @id: [in] Key identifier. Identifier returned during the key creation
 *    smw_generate_key() or smw_import_key().
 *  - @type_name: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with
 *    SMW_KEY_TYPE_NAME_NONE.
 *  - @security_size: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with 0.
 *  - @attributes: [in] If key is present in the SMW's database, it's ignored.
 *    Otherwise, only key's persistency is considered.
 *  - @buffer: Ignored.
 */
struct smw_delete_key_args {
	unsigned char version;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_get_key_attributes_args - Get key attributes arguments
 * @version: [in] Version of this structure
 * @subsystem_name: [out] Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_descriptor: [in/out] Pointer to a Key descriptor object.
 *                  See &struct smw_key_descriptor
 * @key_privacy_name: [out] Key privacy name. See &typedef smw_key_privacy_t
 *
 * The @key_descriptor fields:\
 *
 *  - @id: [in] key identifier. Identifier returned during the key creation
 *    smw_generate_key() or smw_import_key().
 *  - @type_name: [out] Key type name. See &typedef smw_key_type_t
 *  - @security_size: [out] Security size in bits.
 *  - @attributes: [out] Key attributes. see &struct smw_key_attributes
 *  - @buffer: Ignored.
 */
struct smw_get_key_attributes_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_key_privacy_t key_privacy_name;
};

/**
 * struct smw_commit_key_storage_args - Commit non-volatile key storage arguments
 * @version: [in] Version of this structure
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t
 */
struct smw_commit_key_storage_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
};

/**
 * struct smw_key_attestation_args - Device attestation arguments
 * @version: [in] Version of this structure
 * @key_descriptor: [in] Pointer to a Key descriptor object of the key to be
 *                  attested. See &struct smw_key_descriptor
 * @attest_key_descriptor: [in] Pointer to a Key descriptor object of the
 *                         attestation key. See &struct smw_key_descriptor
 * @sign_algo: [in] Signature algorithm and attributes. See &typedef smw_attr_algo_t
 * @challenge: [in] Caller unique ephemeral value (e.g. nonce)
 * @challenge_length: [in] Length in bytes of the challenge value
 * @certificate: [out] Device attestation certificate.
 * @certificate_length: [in/out] Length in bytes of the certificate.
 *
 * The @challenge length depends on the key (refer to the subsystem capabilities).
 * If the length is bigger than expected, it will be cut to keep only the
 * maximum size. If the length is shorter, the challenge value will be completed
 * with 0's.
 *
 * The @key_descriptor and @attest_key_descriptor fields:\
 *
 *  - @id: [in] Key identifier. Identifier returned during the key creation
 *    smw_generate_key() or smw_import_key().
 *  - @type_name: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with
 *    SMW_KEY_TYPE_NAME_NONE.
 *  - @security_size: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with 0.
 *  - @attributes: [in] If key is present in the SMW's database, it's ignored.
 *    Otherwise, only key's persistency is considered.
 *  - @buffer: Ignored.
 *
 * .. note:: Both, key to attest and attestation key, must be owned by the same
 *           subsystem supporting the key attestation operation.
 *
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
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->key_descriptor->type_name is SMW_KEY_TYPE_NAME_NONE.
 *      - @args->key_descriptor->security_size is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_generate_key(struct smw_generate_key_args *args);

/**
 * smw_derive_key() - Derive a Key.
 * @args: Pointer to the structure that contains the Key derivation arguments.
 *
 * This function derives a Key.
 *
 * On operation completion, the @args->key_descriptor_derived->shared_secret_len
 * is updated to the correct value when:\
 *
 *  - Shared secret buffer length is bigger than expected. In this case,
 *    operation succeeds.
 *  - Shared secret buffer length is shorter than expected. In this case,
 *    operation fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->key_descriptor->type_name is SMW_KEY_TYPE_NAME_NONE.
 *      - @args->key_descriptor->security_size is 0.
 *      - If expected to return a shared buffer, @args->key_descriptor_derived
 *        Shared Secret buffer not correctly defined.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 *
 */
enum smw_status_code smw_derive_key(struct smw_derive_key_args *args);

/**
 * smw_import_key() - Import a key.
 * @args: Pointer to the structure that contains the key import arguments.
 *
 * This function imports a key into the storage managed by the Secure Subsystem.
 * The key must be in Secure Subsystem import key supported format, that could
 * be plaintext or specific format conveying key value in encypted mode.
 * Refer to the :ref:`subsystems-capabilities` for more details.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->key_descriptor->type_name is SMW_KEY_TYPE_NAME_NONE.
 *      - @args->key_descriptor->security_size is 0.
 *      - Invalid definition of the key buffer(s).
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_import_key(struct smw_import_key_args *args);

/**
 * smw_export_key() - Export a key.
 * @args: Pointer to the structure that contains the key export arguments.
 *
 * This function exports asymmetric or symmetric key if subsystem owning the
 * key is supporting the operation.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->key_descriptor->id is 0.
 *      - Invalid definition of the key buffer(s).
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_export_key(struct smw_export_key_args *args);

/**
 * smw_delete_key() - Delete a key.
 * @args: Pointer to the structure that contains the key deletion arguments.
 *
 * This function deletes a key.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->key_descriptor->id is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_delete_key(struct smw_delete_key_args *args);

/**
 * smw_get_key_buffers_lengths() - Gets key buffers lengths.
 * @descriptor: [in/out] Pointer to the key descriptor.
 *
 * Two methods are proposed to get the key buffer lengths:\
 *   - Using a valid key identifier, key buffer lengths are key's Secure
 *     Subsystem owner value. Only exportable buffer lengths are returned.
 *   - Using a 0's key identifier, key buffer lengths are standard value.
 *
 * Method 1, the @descriptor fields:\
 *
 *  - @id: [in] Key identifier. Identifier returned during the key creation
 *    smw_generate_key() or smw_import_key().
 *  - @type_name: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with
 *    SMW_KEY_TYPE_NAME_NONE.
 *  - @security_size: [in] **Optional**. If defined but not correct, operation
 *    returns with SMW_STATUS_INVALID_PARAM. Advice to set it with 0.
 *  - @attributes: [in] If key is present in the SMW's database, it's ignored.
 *    Otherwise, only key's persistency is considered.
 *  - @buffer: [out] Key buffer's length are updated. The @format_name is
 *    ignored, lengths are for hexadecimal key buffer value.
 *
 * Method 2, the @descriptor fields:\
 *
 *  - @id: [in] Key identifier must be 0.
 *  - @type_name: [in] **Mandatory**. Define the key type.
 *  - @security_size: [in] **Mandatory**. Define the key security size in bits.
 *  - @attributes: Ignored.
 *  - @buffer: [out] Key buffer's length are updated. The @format_name is
 *    optional, if set, the lengths are calculated function of the format name.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @descriptor is NULL.
 *      - If @key_descriptor->id is 0:\
 *         - @descriptor->type_name is SMW_KEY_TYPE_NAME_NONE.
 *         - @descriptor->security_size is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor);

/**
 * smw_get_key_type_name() - Gets the key type name.
 * @descriptor: [in/out] Pointer to the key descriptor.
 *
 * This function gets the Key type name given the key ID.
 *
 * The @descriptor fields:\
 *
 *  - @id: [in] Key identifier. Identifier returned during the key creation
 *    smw_generate_key() or smw_import_key().
 *  - @type_name: [out] Value updated on success.
 *  - @security_size: Ignored.
 *  - @attributes: Ignored.
 *  - @buffer: Ignored.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      Key type name cannot be retrieved.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_get_key_type_name(struct smw_key_descriptor *descriptor);

/**
 * smw_get_security_size() - Gets the key security size.
 * @descriptor: [in/out] Pointer to the Key descriptor.
 *
 * This function gets the Security size given the key ID.
 *
 * The @descriptor fields:\
 *
 *  - @id: [in] Key identifier. Identifier returned during the key creation
 *    smw_generate_key() or smw_import_key().
 *  - @type_name: Ignored.
 *  - @security_size: [out] Value updated on success.
 *  - @attributes: Ignored.
 *  - @buffer: Ignored.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      Key security size cannot be retrieved.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_get_security_size(struct smw_key_descriptor *descriptor);

/**
 * smw_get_key_attributes() - Get the key attributes.
 * @args: Pointer to the structure that contains the key attributes arguments.
 *
 * This function gets the Key attributes retrieved for the subsystem owning the
 * given key identifier.
 * If some key attributes are not supported, the output values are empty.
 *
 * The @args->subsystem_name field returned is the subsystem name owning
 * the key.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      @args is NULL.
 *  - Other error code from &enum smw_status_code
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
 * .. warning::
 *  Erasing or replacing the Secure Enclave storage may cause an
 *  unrecoverable loss of keys and data. It may also be considered as a
 *  security attack and secure subsystem not more accessible.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      @args is NULL.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_commit_key_storage(struct smw_commit_key_storage_args *args);

/**
 * smw_key_attestation() - Get the key attestation certificate.
 * @args: Pointer to the structure that contains the key attestation arguments.
 *
 * Reads the key attestation certificate.
 *
 * To query the required certificate buffer length, set args->certificate to
 * NULL. The function will then set the required certificate buffer length
 * in @args->certificate_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->certificate_length is updated to the
 * correct value when:\
 *
 *  - Length is bigger than expected. In this case operation succeeded.
 *  - Length is shorter than expected. In this case, operation fails and
 *    returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->key_descriptor->id is 0.
 *      - @args->attest_key_descriptor is NULL.
 *      - @args->attest_key_descriptor->id is 0.
 *      - @args->challenge is NULL and @args->certificate is not NULL.
 *      - @args->challenge is not NULL and @args->challenge_length is 0.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_key_attestation(struct smw_key_attestation_args *args);

#endif /* __SMW_KEYMGR_H__ */
