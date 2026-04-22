/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_CRYPTO_DATA_STORAGE_H__
#define __ELE_CRYPTO_DATA_STORAGE_H__

#include "ele_common.h"

/*******************************************************************************
 * Data Storage definitions
 ******************************************************************************/

/**
 * data_storage_operation_t - Data storage operation
 * DATA_RETRIEVE: Retrieve data
 * DATA_STORE: Store data
 */
typedef enum {
	DATA_RETRIEVE = 0x00UL,
	DATA_STORE = 0x01UL,
} data_storage_operation_t;

/**
 * data_storage_option_t - Data storage option
 * STANDARD_OPTION: Standard option.
 * EL2GO_OPTION: EdgeLock2Go option. When selected, data format must follow the one defined by
 *              EdgeLock2Go API. See documentation for details.
 */
typedef enum {
	STANDARD_OPTION = 0x00UL,
	EL2GO_OPTION = 0x01UL,
} data_storage_option_t;

/**
 * ele_data_storage_t - Data storage structure
 * @data_id: Identifier of the data block (user defined)
 * @data: Address in system memory where data to be store/retrieve can be found
 * @data_size: Data size in bytes
 * @chunk_addr: Output address where encrypted chunk is stored (dynamically allocated)
 * @chunk_size: Output chunk size (additional 36(CHUNK_META_SIZE) Bytes to payload data)
 * @option: Selects the Standard or EL2GO option (only needed for Store operation)
 */
typedef struct {
	uint16_t data_id;
	uint32_t *data;
	size_t data_size;
	uint32_t *chunk_addr;
	size_t chunk_size;
	data_storage_option_t option;
} ele_data_storage_t;

/* Size of additional meta data in chunk */
#define CHUNK_META_SIZE (36u)

/**
 * ele_open_data_storage() - Open Storage Service
 * @mu: MU peripheral base address
 * @keystore_handle_id: Unique session ID obtained by calling ELE_OpenKeystore()
 * @data_storage_id: Pointer where unique storage handle ID word will be stored
 *
 * This function opens data storage service for EdgeLock Enclave.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_open_data_storage(s3mu_t *mu, uint32_t keystore_handle_id,
			       uint32_t *data_storage_id);

/**
 * ele_close_data_storage() - Close ELE Data Storage Service
 * @mu: MU peripheral base address
 * @data_storage_id: Unique session ID obtained by calling ELE_OpenDataStorage()
 *
 * This function closes data storage service for EdgeLock Enclave.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_close_data_storage(s3mu_t *mu, uint32_t data_storage_id);

/**
 * ele_store_data_storage() - Store Data Storage
 * @mu: MU peripheral base address
 * @storage_handle_id: Unique session ID obtained by calling ELE_OpenStorageService()
 * @conf: Pointer where data storage configuration structure can be found
 *
 * This function stores data using EdgeLock Enclave data storage services and
 * places the data at the address specified by conf.chunk_addr. If this address
 * is set to NULL, heap is allocated, the data is placed there, and the allocated heap
 * address is returned in the same variable.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_store_data_storage(s3mu_t *mu, uint32_t storage_handle_id,
				ele_data_storage_t *conf);

/**
 * ele_retrieve_data_storage() - Retrieve Data Storage
 * @mu: MU peripheral base address
 * @storage_handle_id: Unique session ID obtained by calling ELE_OpenStorageService()
 * @conf: Pointer where data storage configuration structure can be found
 *
 * This function retrieves data using EdgeLock Enclave data storage services and
 * places the data at the address specified by conf.data. If this address is set
 * to NULL, heap is allocated, the data is placed there, and the allocated heap
 * address is returned in the same variable.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_InvalidArgument          - Invalid argument parameter
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_retrieve_data_storage(s3mu_t *mu, uint32_t storage_handle_id,
				   ele_data_storage_t *conf);

#endif /* __ELE_CRYPTO_DATA_STORAGE_H__ */
