/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_CRYPTO_KEY_GROUP_MNG_H__
#define __ELE_CRYPTO_KEY_GROUP_MNG_H__

#include "ele_common.h"

/*******************************************************************************
 * Key group manage definitions
 ******************************************************************************/
/**
 * key_group_mng_t - Supported key group manage operations
 * ELE_KEYMNG_LOCK: Lock the key group
 * ELE_KEYMNG_UNLOCK: Unlock the key group
 * ELE_KEYMNG_IMPORT: Import the key group. It will trigger a Storage get chunk.
 * ELE_KEYMNG_EXPORT: Export the key group. It will trigger a Storage chunk export.
 */
typedef enum {
	ELE_KEYMNG_LOCK = 0x1u,
	ELE_KEYMNG_UNLOCK = 0x2u,
	ELE_KEYMNG_IMPORT = 0x4u,
	ELE_KEYMNG_EXPORT = 0x8u,
} key_group_mng_t;

/* Master chunk size is always 100 Bytes */
#define MASTER_CHUNK_SIZE 0x64u
/* Sync operation. The request is completed only when the key group, */
/* keystore and master chunks are exported. */
#define SYNC_OP 0x80u
/* Sync operation. Only Keystore and Master storage chunks are exported. */
#define SYNC_OP_NO_KEY 0x40u
/* Update monotonic counter (anti-rollback protection). */
#define SYNC_MONOTONIC 0x20u

/**
 * ele_chunks_t - ELE chunks structure
 * @master_chunk: Master storage chunk. Always 100 Bytes
 * @keystore_chunk: Key store chunk destination. If null HEAP is used. One per keystore,
 *                   minimal length 64 Bytes, maximal 4160 Bytes
 * @keygroup_chunk: Key group chunk destination. If null HEAP is used. Up to 1024 per keystore,
 *                   minimal length 64 Bytes, maximal 4160 Bytes
 * @keystore_size: Key store chunk size. Set by SW if HEAP for key store destination is used
 * @keygroup_size: Key group chunk size. Set by SW if HEAP for key group destination is used
 */
typedef struct {
	uint8_t master_chunk[MASTER_CHUNK_SIZE];
	uint32_t *keystore_chunk;
	uint32_t *keygroup_chunk;
	size_t keystore_size;
	size_t keygroup_size;
} ele_chunks_t;

/**
 * ele_manage_key_group() - ELE Key Management Service
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID obtained by calling ele_open_key_service()
 * @key_group_id: Unique key group ID
 * @operation: Requested operation, see key_group_mng_t enum
 * @addr: If operation with chunks is requested,
 *        this address is used to either Import or Export chunk.
 * @size: If operation with chunks is requested,
 *        this size is used to either Import or Export chunk.
 *
 * This function provides the Key Group Management Service for EdgeLock Enclave.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_manage_key_group(s3mu_t *mu, uint32_t key_handle_id,
			      uint32_t key_group_id, key_group_mng_t operation,
			      uint32_t *addr, size_t size);

/**
 * ele_export_chunks() - ELE Export Chunks Management Service
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID obtained by calling ele_open_key_service()
 * @export_key_group: If true, key group (key_group_id) chunk is exported,
 *                    if false, only keystore and master
 * @key_group_id: Unique key group ID chosen by user. Not used if export_key_group is false
 * @monotonic: If true, Monotonic counter increment happen (anti-rollback protection)
 * @chunks: ELE Chunks container structure, see ele_chunks_t.
 *
 * This function provides the Key Group Management Service for exporting keygroup,
 * keystore and storage master chunks.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_export_chunks(s3mu_t *mu, uint32_t key_handle_id,
			   bool export_key_group, uint32_t key_group_id,
			   bool monotonic, ele_chunks_t *chunks);

#endif /* __ELE_CRYPTO_KEY_GROUP_MNG_H__ */
