/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023-2025 NXP
 */

#ifndef __KEYMGR_DERIVE_TLS12_H__
#define __KEYMGR_DERIVE_TLS12_H__

#include "keymgr_derive.h"

#include "common.h"

/**
 * seco_derive_tls12() - TLS 1.2 key derivation
 * @seco_ctx: Pointer to the SECO subsystem context structure.
 * @args: Pointer to SMW key derivation arguments.
 *
 * Return:
 * SMW_STATUS_OK			- Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation not supported
 * SMW_STATUS_OUTPUT_TOO_SHORT		- Output buffer length too short
 * SMW_STATUS_INVALID_PARAM		- One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE		- Memory allocation failure
 * SMW_STATUS_UNKNOWN_ID		- Unknown key identifier
 * SMW_STATUS_SUBSYSTEM_FAILURE		- Subsystem failure
 */
int seco_derive_tls12(struct subsystem_context *seco_ctx,
		      struct smw_keymgr_derive_key_args *args);

/**
 * struct seco_tls12_partial_data - TLS1.2 context-specific data
 * @key_exchange_id: TLS1.2 key exchange
 * @prf_id: TLS1.2 Pseudo-Random Function (PRF)
 * @ext_master_key: If true, generates an extended master secret key
 * @peer_public_buffer: Peer public buffer used for ECDH
 * @peer_public_buffer_length: @peer_public_buffer length in bytes
 * @self_public_buffer: Self public buffer used for ECDH
 * @self_public_buffer_length: @self_public_buffer length in bytes
 * @session_hash: The session hash, to be used when @ext_master_key is true
 * @session_hash_length: @session_hash length in bytes
 * @initiator_public_data_type: The key type used for ECDH
 * @key_exchange_scheme: The key exchange scheme used for ECDH
 *
 * SECO subsystem does not support separate TLS1.2 operations (master secret,
 * key expansion), instead it can only execute both in a single call. To be
 * able to support these separate operations, the context that gets passed
 * with the master secret is filled in with this structure. On the subsequent
 * key expansion operation, the input data will be taken from the context. At
 * this point, all the required information should be available to do the
 * call into the SECO firmware.
 */
struct seco_tls12_partial_data {
	enum smw_tls12_key_exchange_id key_exchange_id;
	enum smw_config_hash_algo_id prf_id;
	bool ext_master_key;
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_length;
	unsigned char *self_public_buffer;
	unsigned int self_public_buffer_length;
	unsigned char *session_hash;
	unsigned int session_hash_length;
	hsm_key_type_t initiator_public_data_type;
	hsm_key_exchange_scheme_id_t key_exchange_scheme;
};

/**
 * seco_derive_tls12_op() - TLS 1.2 "Operation-based" key derivation
 * @seco_ctx: Pointer to the SECO subsystem context structure.
 * @args: Pointer to SMW key derivation arguments.
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Operation not supported
 * SMW_STATUS_OUTPUT_TOO_SHORT        - Output buffer length too short
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE           - Memory allocation failure
 * SMW_STATUS_UNKNOWN_ID              - Unknown key identifier
 * SMW_STATUS_SUBSYSTEM_FAILURE       - Subsystem failure
 */
int seco_derive_tls12_op(struct subsystem_context *seco_ctx,
			 struct smw_keymgr_derive_key_args *args);

#endif /* __KEYMGR_DERIVE_TLS12_H__ */
