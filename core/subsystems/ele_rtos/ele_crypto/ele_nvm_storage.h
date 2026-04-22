/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_NVM_STORAGE_H__
#define __ELE_NVM_STORAGE_H__

#include "ele_common.h"

/**
 * nvm_storage_export_req() - ELE Storage Export Request
 * @mu: MU peripheral base address
 * @out: Pointer where the exported chunk will be stored
 * @size: Pointer to the size of the exported chunk in Bytes
 *
 * This function provides Storage Export Request Service for EdgeLock Enclave.
 * This is sent to ELE when it wants to export a chunk to the host.
 * The chunk data is returned in the out parameter and its size in the size parameter.
 *
 * Return:
 * pointer to the exported chunk data if successful, NULL otherwise
 */
uint32_t *nvm_storage_export_req(s3mu_t *mu, uint32_t *out, size_t *size);

/**
 * nvm_storage_get_req() - ELE Storage Get Request
 * @mu: MU peripheral base address
 * @conf: Pointer to the configuration structure for the storage get request
 *
 * This function provides Storage Get Request Service for EdgeLock Enclave.
 * This is sent to ELE when it wants to retrieve a chunk from the host.
 *
 * Return:
 * Status_Success - Success
 * Status_Fail    - Fail
 */
status_t nvm_storage_get_req(s3mu_t *mu, ele_data_storage_t *conf);

#endif /* __ELE_NVM_STORAGE_H__ */
