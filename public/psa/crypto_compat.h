/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __PSA_COMPAT_H__
#define __PSA_COMPAT_H__

#ifndef __PSA_CRYPTO_H__
#error "Do not include this header directly. Instead, include psa/crypto.h"
#endif

/**
 * This file contains declarations that are not part of the PSA specification,
 * but are needed to be present for compatibility with other libraries. These
 * declarations could be possible additions that may be standardized in the future
 * or other extensions.
 *
 * .. warning:
 * These declarations must not be used directly by applications. As much as
 * possible, use only things available in the PSA standard. These are added for
 * the sole purpose of build-time compatibility with other libraries. These
 * are not documented and not supported in the SMW PSA implementation, and may
 * be removed or changed at any time.
 */

struct psa_sign_hash_interruptible_operation_s {
	int dummy;
};
typedef struct psa_sign_hash_interruptible_operation_s
	psa_sign_hash_interruptible_operation_t;
typedef struct psa_sign_hash_interruptible_operation_s
	mbedtls_psa_sign_hash_interruptible_operation_t;

struct psa_verify_hash_interruptible_operation_s {
	int dummy;
};
typedef struct psa_verify_hash_interruptible_operation_s
	psa_verify_hash_interruptible_operation_t;
typedef struct psa_verify_hash_interruptible_operation_s
	mbedtls_psa_verify_hash_interruptible_operation_t;

struct psa_key_agreement_interruptible_operation_s {
	int dummy;
};
typedef struct psa_key_agreement_interruptible_operation_s
	psa_key_agreement_interruptible_operation_t;
typedef struct psa_key_agreement_interruptible_operation_s
	mbedtls_psa_key_agreement_interruptible_operation_t;

typedef psa_key_id_t mbedtls_svc_key_id_t;
#define MBEDTLS_SVC_KEY_ID_INIT PSA_KEY_ID_NULL

static inline int mbedtls_svc_key_id_is_null(mbedtls_svc_key_id_t key)
{
	return key == 0;
}

typedef size_t psa_key_bits_t;

#define PSA_KEY_USAGE_DERIVE_PUBLIC ((psa_key_usage_t)0x00000080)

#define PSA_EXPORT_KEY_PAIR_OR_PUBLIC_MAX_SIZE                                 \
	((PSA_EXPORT_KEY_PAIR_MAX_SIZE > PSA_EXPORT_PUBLIC_KEY_MAX_SIZE) ?     \
		 PSA_EXPORT_KEY_PAIR_MAX_SIZE :                                \
		 PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)

#define PSA_ECDSA_SIGNATURE_SIZE(curve_bits)                                   \
	(PSA_BITS_TO_BYTES(curve_bits) * 2u)

#define PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE                                    \
	PSA_ECDSA_SIGNATURE_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)

#define PSA_ECC_FAMILY_IS_WEIERSTRASS(family) ((family & 0xc0) == 0)

#define PSA_ALG_SIGN_GET_HASH(alg)                                             \
	(PSA_ALG_IS_HASH_AND_SIGN(alg) ?                                       \
		 ((alg) & PSA_ALG_HASH_MASK) | PSA_ALG_CATEGORY_HASH :         \
		 0)

#define PSA_ALG_HMAC_GET_HASH(hmac_alg)                                        \
	(PSA_ALG_CATEGORY_HASH | ((hmac_alg) & PSA_ALG_HASH_MASK))

#endif /* __PSA_COMPAT_H__ */
