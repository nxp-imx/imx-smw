/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_CRYPTO_KEYSTORE_H__
#define __ELE_CRYPTO_KEYSTORE_H__

#include "ele_common.h"

/*******************************************************************************
 * Keystore definitions
 ******************************************************************************/
/**
 * ele_keystore_t - ELE keystore structure
 * @id: User defined word identifying the key store
 * @nonce: Nonce used as authentication proof for accessing the key store
 * @shared: If set TRUE, the key store can be shared among multiple services
 */
typedef struct {
	uint32_t id;
	uint32_t nonce;
	bool shared;
} ele_keystore_t;

/**
 * ele_create_keystore() - Open and Create Key Store
 * @mu: MU peripheral base address
 * @session_id: Unique session ID obtained by calling ele_open_session()
 * @conf: Pointer where keystore configuration structure can be found
 * @keystore_handle_id: Pointer where unique Keystore handle ID word will be stored
 *
 * This function create key store and open key store services in the EdgeLock Enclave.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_create_keystore(s3mu_t *mu, uint32_t session_id,
			     ele_keystore_t *conf,
			     uint32_t *keystore_handle_id);

/**
 * ele_open_keystore() - Open and Create Key Store
 * @mu: MU peripheral base address
 * @session_id: Unique session ID obtained by calling ele_open_session()
 * @conf: Pointer where keystore configuration structure can be found
 * @keystore_handle_id: Pointer where unique Keystore handle ID word will be stored
 * @keystore_chunk: Pointer to Keystore chunk exported via ele_export_chunks()
 * @chunk_size: Size of chunk to be imported. Obtained via ele_export_chunks()
 *
 * This function create key store and open key store services in the EdgeLock Enclave.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_open_keystore(s3mu_t *mu, uint32_t session_id,
			   ele_keystore_t *conf, uint32_t *keystore_handle_id,
			   uint32_t *keystore_chunk, size_t chunk_size);

/**
 * ele_close_keystore() - Close Key Store
 * @mu: MU peripheral base address
 * @keystore_handle_id: Unique session ID obtained by calling ele_open_keystore()
 *
 * This function closes key store and its services in the EdgeLock Enclave.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_close_keystore(s3mu_t *mu, uint32_t keystore_handle_id);

#endif /* __ELE_CRYPTO_KEYSTORE_H__ */
