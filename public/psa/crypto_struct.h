/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
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
 *	PSA Cryptography API v1.1.0
 * Link:
 *	https://developer.arm.com/documentation/ihi0086/b
 */

/* To be defined */
struct psa_aead_operation_s {
	int dummy;
};

/**
 * DOC: PSA_AEAD_OPERATION_INIT
 * This macro returns a suitable initializer for an AEAD operation object of type
 * &typedef psa_aead_operation_t.
 */
#define PSA_AEAD_OPERATION_INIT ((psa_aead_operation_t){ 0 })

static inline struct psa_aead_operation_s psa_aead_operation_init(void)
{
	return PSA_AEAD_OPERATION_INIT;
}

/* To be defined */
struct psa_cipher_operation_s {
	int dummy;
};

/**
 * DOC: PSA_CIPHER_OPERATION_INIT
 * This macro returns a suitable initializer for a cipher operation object of type
 * &typedef psa_cipher_operation_t.
 */
#define PSA_CIPHER_OPERATION_INIT ((psa_cipher_operation_t){ 0 })

static inline struct psa_cipher_operation_s psa_cipher_operation_init(void)
{
	return PSA_CIPHER_OPERATION_INIT;
}

/* To be defined */
struct psa_hash_operation_s {
	int dummy;
};

/**
 * DOC: PSA_HASH_OPERATION_INIT
 * This macro returns a suitable initializer for a hash operation object of type
 * &typedef psa_hash_operation_t.
 */
#define PSA_HASH_OPERATION_INIT ((psa_hash_operation_t){ 0 })

static inline struct psa_hash_operation_s psa_hash_operation_init(void)
{
	return PSA_HASH_OPERATION_INIT;
}

struct psa_key_attributes_s {
	psa_key_id_t id;
	psa_key_lifetime_t lifetime;
	psa_key_type_t type;
	size_t bits;
	psa_key_usage_t usage_flags;
	psa_algorithm_t alg;
};

#define PSA_KEY_ATTRIBUTES_INIT ((psa_key_attributes_t){ 0, 0, 0, 0, 0, 0 })

static inline struct psa_key_attributes_s psa_key_attributes_init(void)
{
	return PSA_KEY_ATTRIBUTES_INIT;
}

/* To be defined */
struct psa_key_derivation_operation_s {
	int dummy;
};

/**
 * DOC: PSA_KEY_DERIVATION_OPERATION_INIT
 * This macro returns a suitable initializer for a key derivation operation object of type
 * &typedef psa_key_derivation_operation_t.
 */
#define PSA_KEY_DERIVATION_OPERATION_INIT                                      \
	((psa_key_derivation_operation_t){ 0 })

static inline struct psa_key_derivation_operation_s
psa_key_derivation_operation_init(void)
{
	return PSA_KEY_DERIVATION_OPERATION_INIT;
}

/* To be defined */
struct psa_mac_operation_s {
	int dummy;
};

/**
 * DOC: PSA_MAC_OPERATION_INIT
 * This macro returns a suitable initializer for a MAC operation object of type
 * &typedef psa_mac_operation_t.
 */
#define PSA_MAC_OPERATION_INIT ((psa_mac_operation_t){ 0 })

static inline struct psa_mac_operation_s psa_mac_operation_init(void)
{
	return PSA_MAC_OPERATION_INIT;
}

static inline void psa_set_key_id(psa_key_attributes_t *attributes,
				  psa_key_id_t key)
{
	psa_key_lifetime_t lifetime;
	psa_key_location_t location;

	attributes->id = key;

	location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);
	lifetime = PSA_KEY_LIFETIME_GET_LIFETIME(PSA_KEY_LIFETIME_PERSISTENT,
						 location);

	if (PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime))
		attributes->lifetime = lifetime;
}

static inline psa_key_id_t
psa_get_key_id(const psa_key_attributes_t *attributes)
{
	return attributes->id;
}

static inline void psa_set_key_lifetime(psa_key_attributes_t *attributes,
					psa_key_lifetime_t lifetime)
{
	attributes->lifetime = lifetime;
	if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime))
		attributes->id = 0;
}

static inline psa_key_lifetime_t
psa_get_key_lifetime(const psa_key_attributes_t *attributes)
{
	return attributes->lifetime;
}

static inline void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
					   psa_key_usage_t usage_flags)
{
	attributes->usage_flags = usage_flags;
}

static inline psa_key_usage_t
psa_get_key_usage_flags(const psa_key_attributes_t *attributes)
{
	psa_key_usage_t usages = attributes->usage_flags;

	/*
	 * DOC: Reference
	 * Documentation: PSA Cryptography API v1.1.0
	 * Link: https://developer.arm.com/documentation/ihi0086/b
	 */
	if (usages & PSA_KEY_USAGE_SIGN_HASH)
		usages |= PSA_KEY_USAGE_SIGN_MESSAGE;

	if (usages & PSA_KEY_USAGE_VERIFY_HASH)
		usages |= PSA_KEY_USAGE_VERIFY_MESSAGE;

	return usages;
}

static inline void psa_set_key_algorithm(psa_key_attributes_t *attributes,
					 psa_algorithm_t alg)
{
	attributes->alg = alg;
}

static inline psa_algorithm_t
psa_get_key_algorithm(const psa_key_attributes_t *attributes)
{
	return attributes->alg;
}

static inline void psa_set_key_type(psa_key_attributes_t *attributes,
				    psa_key_type_t type)
{
	attributes->type = type;
}

static inline psa_key_type_t
psa_get_key_type(const psa_key_attributes_t *attributes)
{
	return attributes->type;
}

static inline void psa_set_key_bits(psa_key_attributes_t *attributes,
				    size_t bits)
{
	attributes->bits = bits;
}

static inline size_t psa_get_key_bits(const psa_key_attributes_t *attributes)
{
	return attributes->bits;
}

#endif /* __PSA_CRYPTO_STRUCT_H__ */
