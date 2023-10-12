/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */

#ifndef __SMW_STRINGS_H__
#define __SMW_STRINGS_H__

typedef const char *smw_string_t;

/**
 * typedef smw_subsystem_t - Subsystem name
 * Values:
 *	- TEE
 *	- HSM
 */
typedef smw_string_t smw_subsystem_t;

/**
 * typedef smw_key_type_t - Key type name
 * Values:
 *	- NIST
 *	- BRAINPOOL_R1
 *	- BRAINPOOL_T1
 *	- AES
 *	- DES
 *	- DES3
 *	- DSA_SM2_FP
 *	- SM4
 *	- HMAC
 *	- HMAC_MD5
 *	- HMAC_SHA1
 *	- HMAC_SHA224
 *	- HMAC_SHA256
 *	- HMAC_SHA384
 *	- HMAC_SHA512
 *	- HMAC_SM3
 *	- RSA
 */
typedef smw_string_t smw_key_type_t;

/**
 * typedef smw_keymgr_privacy_t - Key privacy name
 * Values:
 *	- PUBLIC
 *	- PRIVATE
 *	- KEYPAIR
 */
typedef smw_string_t smw_keymgr_privacy_t;

/**
 * typedef smw_keymgr_persistence_t - Key persistence name
 * Values:
 *	- TRANSIENT
 *	- PERSISTENT
 *	- PERMANENT
 */
typedef smw_string_t smw_keymgr_persistence_t;

/**
 * typedef smw_hash_algo_t - Hash algorithm name
 * Values:
 *	- MD5
 *	- SHA1
 *	- SHA224
 *	- SHA256
 *	- SHA384
 *	- SHA512
 *	- SM3
 */
typedef smw_string_t smw_hash_algo_t;

/**
 * typedef smw_mac_algo_t - MAC algorithm name
 * Values:
 *	- CMAC
 *	- CMAC_TRUNCATED
 *	- HMAC
 *	- HMAC_TRUNCATED
 */
typedef smw_string_t smw_mac_algo_t;

/**
 * typedef smw_cipher_mode_t - Cipher mode name
 * Values:
 *	- CBC
 *	- CTR
 *	- CTS
 *	- ECB
 *	- XTS
 */
typedef smw_string_t smw_cipher_mode_t;
/**
 * typedef smw_aead_mode_t - AEAD mode name
 * Values:
 *	- CCM
 *	- GCM
 */
typedef smw_string_t smw_aead_mode_t;

/**
 * typedef smw_cipher_operation_t - Cipher operation name
 * Values:
 *	- ENCRYPT
 *	- DECRYPT
 */
typedef smw_string_t smw_cipher_operation_t;

/**
 * typedef smw_aead_operation_t - AEAD operation name
 * Values:
 *	- ENCRYPT
 *	- DECRYPT
 */
typedef smw_string_t smw_aead_operation_t;

/**
 * typedef smw_key_format_t - Key format name
 * Values:
 *	- HEX: hexadecimal value (no encoding)
 *	- BASE64: base 64 encoding value
 */
typedef smw_string_t smw_key_format_t;

/**
 * typedef smw_attr_key_type_t - Key definition attribute type name
 *
 * An attribute is encoded with a Type-Length-Value (TLV) format.
 * Function of the attribute type, the TLV scheme varies.
 * Refer to :doc:`/tlv/tlv`
 *
 * Key Manager attributes:
 * The following :numref:`key_manager_attributes` lists all TLV attributes
 * supported by key manager operations like generate, import, derive, delete.
 *
 * .. table:: Key manager attributes
 *    :name: key_manager_attributes
 *    :align: center
 *    :widths: 25 14 62
 *    :width: 100%
 *    :class: wrap-table
 *
 *    +-----------------+--------------+---------------------------------------+
 *    | **Type Value**  | **Encoding** | **Description**                       |
 *    +=================+==============+=======================================+
 *    | PERSISTENT      | boolean      | If present key is persistent.         |
 *    +-----------------+--------------+---------------------------------------+
 *    | RSA_PUB_EXP     | numeral      | Setup the RSA Public exponent value.  |
 *    |                 |              | The default value is 65537 if this    |
 *    |                 |              | attribute is not defined.             |
 *    +-----------------+--------------+---------------------------------------+
 *    | FLUSH_KEY       | boolean      | If present, ensure that the key       |
 *    |                 |              | storage is up to date.                |
 *    +-----------------+--------------+---------------------------------------+
 *    | POLICY          | variable     | This attribute is used to restrict    |
 *    |                 | length list  | the key usage(s) and algorithm(s).    |
 *    |                 |              | The following `Key policy`_ details   |
 *    |                 |              | how a key policy is defined.          |
 *    +-----------------+--------------+---------------------------------------+
 *    | STORAGE_ID      | numeral      | Subsystem storage identifier.         |
 *    |                 |              | EdgeLock 2GO storage identifiers:     |
 *    |                 |              |  - Key object: NXP_EL2GO_KEY          |
 *    |                 |              |  - Data object: NXP_EL2GO_DATA        |
 *    +-----------------+--------------+---------------------------------------+
 *
 * Key policy
 * """"""""""
 * The key policy is built with a TLV variable length list in which one or more
 * key usage(s) are listed. To each key usage, algorithm(s) might be restricted.
 *
 * This attribute may or may not be significative (fully or partially) function
 * of the subsystem handling the key. Refer to the :doc:`/capabilities`
 * for more details.
 *
 * Signature attributes:
 *
 * The following :numref:`signature_attributes` lists all TLV attributes
 * supported by sign and verify operations.
 *
 * .. table:: Signature attributes
 *    :name: signature_attributes
 *    :align: center
 *    :widths: 25 14 62
 *    :width: 100%
 *    :class: wrap-table
 *
 *    +-----------------+--------------+---------------------------------------+
 *    | **Type Value**  | **Encoding** | **Description**                       |
 *    +=================+==============+=======================================+
 *    | SIGNATURE_TYPE  | string       | Define the type of signature in case  |
 *    |                 |              | multiple options are possible.        |
 *    |                 |              | Otherwise the signature type is       |
 *    |                 |              | function of the key type.             |
 *    |                 |              | Refer to `smw_signature_type_t`_      |
 *    |                 |              | to get the possible attribute value.  |
 *    +-----------------+--------------+---------------------------------------+
 *    | SALT_LENGTH     | string       | If signature is RSASSA-PSS, set the   |
 *    |                 |              | salt length of the signature.         |
 *    +-----------------+--------------+---------------------------------------+
 *    | TLS_MAC_FINISH  | string       | Define the TLS finish message         |
 *    |                 |              | signature type to generate. Value is  |
 *    |                 |              | either "CLIENT" or "SERVER"           |
 *    |                 |              | corresponding to client or server     |
 *    |                 |              | finish signature.                     |
 *    +-----------------+--------------+---------------------------------------+
 *
 */
typedef smw_string_t smw_attr_key_type_t;

/**
 * typedef smw_attr_data_type_t - Data definition attribute type name
 *
 * An attribute is encoded with a Type-Length-Value (TLV) format.
 * Function of the attribute type, the TLV scheme varies.
 * Refer to :doc:`/tlv/tlv`
 *
 * The following :numref:`data_manager_attributes` lists all TLV attributes
 * supported by data manager store operation.
 *
 * .. table:: Data manager attributes
 *    :name: data_manager_attributes
 *    :align: center
 *    :widths: 25 14 62
 *    :width: 100%
 *    :class: wrap-table
 *
 *    +-----------------+--------------+---------------------------------------+
 *    | **Type Value**  | **Encoding** | **Description**                       |
 *    +=================+==============+=======================================+
 *    | READ_ONLY       | boolean      | Data is read-only.                    |
 *    +-----------------+--------------+---------------------------------------+
 *    | READ_ONCE       | boolean      | Data is read once time, when data is  |
 *    |                 |              | retrieved, data is deleted.           |
 *    +-----------------+--------------+---------------------------------------+
 *    | LIFECYCLE       | variable     | This attribute is used to restrict    |
 *    |                 | length list  | the data accessibility.               |
 *    |                 |              | The following `Data lifecycle`_ gives |
 *    |                 |              | more details.                         |
 *    +-----------------+--------------+---------------------------------------+
 *
 * Data lifecycle
 * """"""""""""""
 * The data lifecycle is built with a TLV variable length list in which one or
 * more string below. This attribute limits the access of the data in the
 * corresponding device lifecycle.
 *
 * The CURRENT string value means that data is accessible only in the current
 * device lifecycle when data is created.
 *
 * .. table:: Data lifecyle attribute
 *    :name: data_lifecycle_attribute
 *    :align: center
 *    :class: wrap-table
 *
 *    +------------------+
 *    | **String Value** |
 *    +==================+
 *    | OPEN             |
 *    +------------------+
 *    | CLOSED           |
 *    +------------------+
 *    | CLOSED_LOCKED    |
 *    +------------------+
 *    | CURRENT          |
 *    +------------------+
 *
 * This attribute may or may not be significative (fully or partially) function
 * of the subsystem handling the data. Refer to the :doc:`/capabilities`
 * for more details.
 *
 *
 */
typedef smw_string_t smw_attr_data_type_t;

/**
 * typedef smw_signature_type_t - Signature type name
 * Values:
 *	- DEFAULT
 *	- RSASSA-PKCS1-V1_5
 *	- RSASSA-PSS
 */
typedef smw_string_t smw_signature_type_t;

/**
 * typedef smw_kdf_t - Key derivation function name
 * Values:
 *	- TLS12_KEY_EXCHANGE
 */
typedef smw_string_t smw_kdf_t;

/**
 * typedef smw_tls12_kea_t - TLS 1.2 Key exchange algorithm name
 * Values:
 *	- DH_DSS
 *	- DH_RSA
 *	- DHE_DSS
 *	- DHE_RSA
 *	- ECDH_ECDSA
 *	- ECDH_RSA
 *	- ECDHE_ECDSA
 *	- ECDHE_RSA
 *	- RSA
 */
typedef smw_string_t smw_tls12_kea_t;

/**
 * typedef smw_tls12_enc_t - TLS 1.2 encryption algorithm name
 * Values:
 *	- 3DES_EDE_CBC
 *	- AES_128_CBC
 *	- AES_128_GCM
 *	- AES_256_CBC
 *	- AES_256_GCM
 *	- RC4_128
 */
typedef smw_string_t smw_tls12_enc_t;

/**
 * typedef smw_lifecycle_t - Device lifecycle name
 * Values:
 *	- OPEN
 *	- CLOSED
 *	- CLOSED_LOCKED
 *	- OEM_RETURN
 *	- NXP_RETURN
 */
typedef smw_string_t smw_lifecycle_t;

#endif /* __SMW_STRINGS_H__ */
