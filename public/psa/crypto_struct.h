/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_CRYPTO_STRUCT_H__
#define __PSA_CRYPTO_STRUCT_H__

/**
 * DOC:
 * This file contains the definitions of the data structures exposed by the PSA Cryptography API.
 */

/**
 * DOC: Reference
 * Documentation:
 *	PSA Cryptography API v1.0.1
 * Link:
 *	https://developer.arm.com/documentation/ihi0086/a
 */

/* To be defined */
struct psa_aead_operation {
	int dummy;
};

/**
 * DOC: PSA_AEAD_OPERATION_INIT
 * This macro returns a suitable initializer for an AEAD operation object of type
 * &typedef psa_aead_operation_t.
 */
#define PSA_AEAD_OPERATION_INIT ((psa_aead_operation_t){ 0 })

/* To be defined */
struct psa_cipher_operation {
	int dummy;
};

/**
 * DOC: PSA_CIPHER_OPERATION_INIT
 * This macro returns a suitable initializer for a cipher operation object of type
 * &typedef psa_cipher_operation_t.
 */
#define PSA_CIPHER_OPERATION_INIT ((psa_cipher_operation_t){ 0 })

/* To be defined */
struct psa_hash_operation {
	int dummy;
};

/**
 * DOC: PSA_HASH_OPERATION_INIT
 * This macro returns a suitable initializer for a hash operation object of type
 * &typedef psa_hash_operation_t.
 */
#define PSA_HASH_OPERATION_INIT ((psa_hash_operation_t){ 0 })

/* To be defined */
struct psa_key_attributes {
	int dummy;
};

/**
 * DOC: PSA_KEY_ATTRIBUTES_INIT
 * This macro returns a suitable initializer for a key attribute object of type
 * &typedef psa_key_attributes_t.
 */
#define PSA_KEY_ATTRIBUTES_INIT ((psa_key_attributes_t){ 0 })

/* To be defined */
struct psa_key_derivation_operation {
	int dummy;
};

/**
 * DOC: PSA_KEY_DERIVATION_OPERATION_INIT
 * This macro returns a suitable initializer for a key derivation operation object of type
 * &typedef psa_key_derivation_operation_t.
 */
#define PSA_KEY_DERIVATION_OPERATION_INIT                                      \
	((psa_key_derivation_operation_t){ 0 })

/* To be defined */
struct psa_mac_operation {
	int dummy;
};

/**
 * DOC: PSA_MAC_OPERATION_INIT
 * This macro returns a suitable initializer for a MAC operation object of type
 * &typedef psa_mac_operation_t.
 */
#define PSA_MAC_OPERATION_INIT ((psa_mac_operation_t){ 0 })

#endif /* __PSA_CRYPTO_STRUCT_H__ */
