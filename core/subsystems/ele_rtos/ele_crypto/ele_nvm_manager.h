/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_NVM_MANAGER_H__
#define __ELE_NVM_MANAGER_H__

#include "ele_crypto_key_group_mng.h"

#include "s3mu.h"

#define STORAGE_MASTER_BLOB_ID 0

/*******************************************************************************
 * NVM Manager
 ******************************************************************************/
typedef struct {
	/**
	 * Write to NVM
	 * @blob_id_msb:   1st part of the unique 64 bit identifier of the data
	 * @blob_id_lsb:   2nd part of the unique 64 bit identifier of the data
	 * @blob_id_ext:   Blob ID extension
	 * @chunk:         Data to copy to NVM.
	 * @chunk_sz:      Size of data to be copied.
	 *
	 * This function writes data identified by the two-part blob ID and blob_ext to NVM.
	 *
	 *
	 * @return Status Status_Success if success, Status_Fail if fail
	 * Return:
	 * Status_Success  - Success
	 * Status_Fail     - Fail
	 */
	status_t (*nvm_write)(uint32_t blob_id_msb, uint32_t blob_id_lsb,
			      uint32_t blob_ext, uint32_t *chunk,
			      size_t chunk_sz);

	/**
	 * Read from NVM
	 * @blob_id_msb:   1st part of the unique 64 bit identifier of the data
	 * @blob_id_lsb:   2nd part of the unique 64 bit identifier of the data
	 * @blob_id_ext:   Blob ID extension
	 * @chunk:         Buffer to copy the data in.
	 * @sz:            [in] Size of chunk if not NULL
	 *                      [out] Size of the data read form NVM.
	 *
	 * This function reads data identified by the two-part blob ID and blob_ext
	 * from NVM and returns it.
	 *
	 * Return:
	 * Status_Success  - Success
	 * Status_Fail     - Fail
	 */
	status_t (*nvm_read)(uint32_t blob_id_msb, uint32_t blob_id_lsb,
			     uint32_t blob_id_ext, uint32_t *chunk, size_t *sz);
} ele_nvm_manager_t;

/**
 * ele_register_nvm_manager() - Register NVM manager with ELE subsystem
 * @manager: Pointer to NVM manager structure with read/write callbacks
 *
 * This function registers an NVM manager with the ELE subsystem. The manager
 * must provide valid read and write callback functions for NVM operations.
 * Only one NVM manager can be registered at a time.
 *
 * Return:
 * Status_Success - on successful registration
 * Status_Fail - if manager is NULL or callbacks are invalid, or allocation fails
 * Status_Busy - if an NVM manager is already registered
 */
status_t ele_register_nvm_manager(ele_nvm_manager_t *manager);

/**
 * ele_unregister_nvm_manager() - Unregister the NVM manager from ELE subsystem
 *
 * This function unregisters the currently registered NVM manager and frees
 * the associated resources. After calling this function, NVM operations
 * will not be available until a new manager is registered.
 *
 * Return:
 * Status_Success - always returns success
 */
status_t ele_unregister_nvm_manager(void);

/**
 * ele_get_nvm_manager() - Get the registered NVM manager
 *
 * This function returns a pointer to the currently registered NVM manager.
 * If no manager is registered, it returns NULL.
 *
 * Return:
 * Pointer to the registered NVM manager, or NULL if none is registered.
 */
ele_nvm_manager_t *ele_get_nvm_manager(void);

/**
 * ele_manage_key_group_to_nvm() - Manage key groups in NVM
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID from ele_open_key_service()
 * @key_group_id: Unique key group ID to manage
 * @operation: Requested operation (see key_group_mng_t enum)
 *
 * This function provides the Key Group Management Service for EdgeLock
 * Enclave. It allows performing various operations on key groups stored
 * in NVM, such as create, delete, or update operations.
 *
 * Return:
 * Status_Success - on successful key group management
 * Status_Fail - on failure
 */
status_t ele_manage_key_group_to_nvm(s3mu_t *mu, uint32_t key_handle_id,
				     uint32_t key_group_id,
				     key_group_mng_t operation);

/**
 * ele_storage_master_import_from_nvm() - Import storage master from NVM
 * @mu: MU peripheral base address
 * @nvm_storage_id: Unique session ID from ele_open_nvm_storage_service()
 *
 * This function provides Storage Master Import Service for EdgeLock Enclave.
 * This must be called prior to opening keystore stored in the NVM. It reads
 * the master chunk from NVM using the registered NVM manager and imports it
 * into ELE.
 *
 * Return:
 * Status_Success - on successful master import
 * Status_Fail - on failure or if NVM manager is not registered
 * Status_NoData - if master chunk doesn't exist in NVM
 */
status_t ele_storage_master_import_from_nvm(s3mu_t *mu,
					    uint32_t nvm_storage_id);

/**
 * ele_export_chunks_to_nvm() - Export key chunks to NVM using NVM Manager
 * @mu: MU peripheral base address
 * @key_handle_id: Unique key management handle ID from ele_open_key_service()
 * @export_key_group: If true, export key group chunk; if false, only keystore and master
 * @key_group_id: Unique key group ID chosen by user (ignored if export_key_group is false)
 *
 * This function provides the Key Group Management Service for exporting
 * keygroup, keystore and storage master chunks to NVM. It sends the
 * appropriate command to EdgeLock Enclave and waits for the response.
 *
 * Return:
 * Status_Success - on successful chunk export
 * Status_Fail - on failure
 */
status_t ele_export_chunks_to_nvm(s3mu_t *mu, uint32_t key_handle_id,
				  bool export_key_group, uint32_t key_group_id);

#endif /* __ELE_NVM_MANAGER_H__ */
