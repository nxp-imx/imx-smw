/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_NVM_SERVICE_H__
#define __ELE_NVM_SERVICE_H__

#include "ele_common.h"

/**
 * ele_open_nvm_storage_service() - Open NVM Storage Service
 * @mu: MU peripheral base address
 * @session_id: Unique session ID obtained by calling ele_open_session()
 * @nvm_storage_id: Pointer where unique NVM storage handle ID word will be stored
 *
 * This function opens non-volatile storage services for EdgeLock Enclave.
 * Service is used for importing and exporting data to/from ELE.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_open_nvm_storage_service(s3mu_t *mu, uint32_t session_id,
				      uint32_t *nvm_storage_id);

/**
 * ele_close_nvm_storage_service() - Close ELE NVM Storage Service
 * @mu: MU peripheral base address
 * @nvm_storage_id: Unique session ID obtained by calling ele_open_nvm_storage_service()
 *
 * This function closes Non-volatile memory storage service for EdgeLock Enclave.
 * Service is used for importing and exporting data to/from ELE.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_close_nvm_storage_service(s3mu_t *mu, uint32_t nvm_storage_id);

/**
 * ele_storage_export_finish() - ELE Storage Master Export Finish
 * @mu: MU peripheral base address
 * @nvm_storage_id: Unique session ID obtained by calling ele_open_nvm_storage_service()
 *
 * This function provides Storage Master Export Finish Service for EdgeLock Enclave.
 * This is sent to ELE as acknowledgment after exporting master chunk.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_storage_export_finish(s3mu_t *mu, uint32_t nvm_storage_id);

/**
 * ele_storage_master_import() - ELE Storage Master Import Service
 * @mu: MU peripheral base address
 * @nvm_storage_id: Unique session ID obtained by calling ele_open_nvm_storage_service()
 * @addr: Address of storage master chunk to be imported
 *
 * This function provides Storage Master Import Service for EdgeLock Enclave.
 * This must be called prior opening keystore stored in the NVM.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t ele_storage_master_import(s3mu_t *mu, uint32_t nvm_storage_id,
				   uint32_t *addr);

#endif /* __ELE_NVM_SERVICE_H__ */
