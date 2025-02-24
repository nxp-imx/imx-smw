/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __KEYMGR_DERIVE_TLS12_H__
#define __KEYMGR_DERIVE_TLS12_H__

#include "common.h"

/**
 * struct tls12_ms_ele_op_payload - Key Exchange input content
 *                                  (TLS 1.2 Master Secret)
 * @ver: Version of this structure
 * @rsv: Reserved (should be set to 0)
 * @keystore_id: Key store ID
 * @tls1_2_algo: TLS1.2 algo to be used for Key derivation process
 * @key_id: Base Key ID
 * @key_type: Derived Key type
 * @key_size: Derived Key size in bits
 * @key_lifetime: Derived Key lifetime
 * @key_usage: Derived Key usage
 * @key_permitted_algo: Derived Key permitted algo
 * @key_lifecycle:  Derived Key lifecycle
 * @derived_key_id: Derived Key ID
 * @reserved: Reserved (should be set to 0)
 *
 * The ELE library expects that op_key_exchange_args_t.in_content is set to
 * a pointer to a structure that is specific for that key exchange operation.
 * It defines this structure layout internally for the master key generation,
 * but it does not export it. Define the same structure here with slightly
 * modified member names, in the same spirit as hkdf_ele_op_payload.
 *
 * @ver should always be set to 1.
 *
 * @tls1_2_algo should be set to HSM_KEY_DERIVATION_TLS1_2_MASTER_SECRET_SHAXXX
 *
 * @key_type, @key_size, @key_lifetime, @key_usage, @key_permitted_algo and @key_lifecycle
 * are all ignored by ELE. However, if the master key is stored inside ELE, these values
 * will then be set to the values chosen by ELE.
 */
struct tls12_ms_ele_op_payload {
	uint16_t ver;
	uint16_t rsv;
	uint32_t keystore_id;
	uint32_t tls1_2_algo;
	uint32_t key_id;
	uint16_t key_type;	     /* ignored */
	uint16_t key_size;	     /* ignored */
	uint32_t key_lifetime;	     /* ignored */
	uint32_t key_usage;	     /* ignored */
	uint32_t key_permitted_algo; /* ignored */
	uint32_t key_lifecycle;	     /* ignored */
	uint32_t derived_key_id;
	uint32_t reserved;
};

/**
 * struct tls12_kb_ele_op_payload - Key Exchange input content
 *                                  (TLS 1.2 Key Block / IVs / Verify Data generation)
 * @ver: Version of this structure
 * @rsv: Reserved (should be set to 0)
 * @keystore_id: Key store ID
 * @tls1_2_algo: TLS1.2 algo to be used for Key derivation process
 * @key_id: Master Secret Key ID
 * @key_type: Derived Key type
 * @ciphersuite_key_bits_size: The size in bits of the generated keys
 * @key_lifetime: Derived Key lifetime
 * @key_usage: Derived Key usage
 * @ciphersuite_algorithm: The selected ciphersuite algorithm
 * @key_permitted_algo: Derived Key permitted algo
 * @key_lifecycle:  Derived Key lifecycle
 * @derived_key_id: Derived Key ID
 * @master_secret: Optionally, pass the master secret to ELE as a data buffer
 * @master_secret_len: The length of the master secret data buffer
 *
 * The ELE library expects that op_key_exchange_args_t.in_content is set to
 * a pointer to a structure that is specific for that key exchange operation.
 * It defines this structure layout internally but it does not export it.
 * Define the same structure here with slightly modified member names,
 * in the same spirit as hkdf_ele_op_payload.
 *
 * This structure can be used to generate the Key Block, IVs, and Verify Data,
 * since it's the same operation (the TLS1.2 KDF), only with different input
 * and different data is extracted from the output.
 *
 * @ver should always be set to 1.
 *
 * @tls1_2_algo should be set to HSM_KEY_DERIVATION_TLS1_2_KEY_BLOCK_SHA*** /
 *                               HSM_KEY_DERIVATION_TLS1_2_IV_SHA*** /
 *                               HSM_KEY_DERIVATION_TLS1_2_VERIFY_DATA_SHA***
 *
 * @cipher_bits and @cipher_algo should be set to the appropriate
 * values for the selected TLS 1.2 ciphersuite, e.g.
 * ECDHE-ECDSA-AES128-GCM-SHA256: cipher_bits=128, cipher_algo=PERMITTED_ALGO_GCM
 *
 * @key_type, @key_lifetime, @key_usage, and @key_lifecycle are all ignored by ELE.
 * However, if any of the resulting keys (Key Block) are stored inside ELE, these
 * values will then be set to the values chosen by ELE.
 */
struct tls12_kb_ele_op_payload {
	uint16_t ver;
	uint16_t rsv;
	uint32_t keystore_id;
	uint32_t tls1_2_algo;
	uint32_t key_id;
	uint16_t key_type; /* ignored */
	uint16_t cipher_bits;
	uint32_t key_lifetime; /* ignored */
	uint32_t key_usage;    /* ignored */
	uint32_t cipher_algo;
	uint32_t key_lifecycle; /* ignored */
	uint32_t derived_key_id;
	uint32_t master_secret_len;
	uint8_t master_secret[48];
};

#endif /* __KEYMGR_DERIVE_TLS12_H__ */
