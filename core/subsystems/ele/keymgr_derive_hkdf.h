/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __KEYMGR_DERIVE_HKDF_H__
#define __KEYMGR_DERIVE_HKDF_H__

#include "common.h"

/**
 * struct hkdf_ele_op_payload - Key Exchange input content (HKDF FULL/HKDF
 *                               Extract/HKDF Expand) member argument
 * @ver: Version of this structure
 * @rsv: Reserved bits
 * @keystore_id: Key store ID
 * @hkdf_algo: HKDF algo to be used for Key derivation process
 * @key_id: Base Key ID
 * @key_type: Derived Key type
 * @key_size: Derived Key size in bits
 * @key_lifetime: Derived Key lifetime
 * @key_usage: Derived Key usage
 * @key_permit_algo: Derived Key permitted algo
 * @key_lifecycle:  Derived Key lifecycle
 * @derived_key_id: Derived Key ID
 * @buffer_len: Buffer length
 *
 * In the ELE SE library, the in_content member of
 * struct op_key_exchange_args_t defined as a uint8_t pointer, is provided,
 * with no information on what it should point to.
 * This is why I defined this structure.
 *
 * The in_content member points to a memory block that contains
 * struct hkdf_ele_op_payload followed by the
 *  - PRK buffer if set for HKDF Expand step.
 *  - Salt buffer if set for HKDF Full and Extract step.
 *
 * @ver supported is 1.
 *
 * @buffer_len - It should hold the salt buffer length for HKDF Full/Extract
 * step. For HKDF Expand step, it should hold PRK buffer length if PRK is
 * exported.
 *
 * @key_id - For HKDF Full/Extract step, it should hold the private key ID to be
 * used along with peer public key to generate ECDH IKM.
 * For HKDF Expand step, it should hold the PRK ID, if PRK is already stored
 * in the ELE storage.
 *
 * HKDF Extract:
 * - @key_type, @key_lifetime, @key_usage, @key_permit_algo, @key_lifecycle are
 *   not used and ignored if the PRK to be exported.
 * - @key_lifetime and @key_lifecycle should be set if PRK to be stored in ELE.
 *
 * HKDF Full/Expand:
 * - @key_type, @key_lifetime, @key_usage, @key_permit_algo, @key_lifecycle are
 *   not used and ignored if the derived key to be exported. Otherwise, these
 *   parameters must be set.
 */

struct hkdf_ele_op_payload {
	uint16_t ver;
	uint16_t rsv;
	uint32_t keystore_id;
	uint32_t hkdf_algo;
	uint32_t key_id;
	uint16_t key_type;
	uint16_t key_size;
	uint32_t key_lifetime;
	uint32_t key_usage;
	uint32_t key_permit_algo;
	uint32_t key_lifecycle;
	uint32_t derived_key_id;
	uint32_t buffer_len;
};

#endif /* __KEYMGR_DERIVE_HKDF_H__ */
