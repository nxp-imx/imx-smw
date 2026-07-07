/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __ELE_CRYPTO_H__
#define __ELE_CRYPTO_H__

#include <stdbool.h>

#include "ele_common.h"

/**
 * ele_load_fw() - Load ELE FW
 * @mu: MU peripheral base address
 * @fw: In system memory where FW can be found
 * @fw_size: Size of the FW in bytes
 *
 * This function Loads firmware into EdgeLock Enclave.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_load_fw(s3mu_t *mu, const uint8_t *fw, size_t fw_size);

/**
 * ele_init_services() - Initialize ELE services
 * @mu: MU peripheral base address
 *
 * This function initializes the EdgeLock Enclave services and needs to be
 * called at least once before using these services (e.g. ele_open_session()).
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_init_services(s3mu_t *mu);

/**
 * ele_open_session() - Open ELE Session
 * @mu: MU peripheral base address
 * @session_id: Pointer to output unique session ID word
 *
 * This function opens Session for EdgeLock Enclave.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_open_session(s3mu_t *mu, uint32_t *session_id);

/**
 * ele_close_session() - Close ELE Session
 * @mu: MU peripheral base address
 * @session_id: Unique session ID obtained by calling ele_open_session()
 *
 * This function closes the Session for EdgeLock Enclave.
 *
 * Return:
 * STATUS_SUCCESS - Success
 * STATUS_FAIL    - Fail
 */
status_t ele_close_session(s3mu_t *mu, uint32_t session_id);

/**
 * ele_ping() - Ping ELE
 * @mu: MU peripheral base address
 *
 * This function Ping EdgeLock Enclave, can be sent at any time to verify ELE is alive.
 * Additionally, this command reloads the fuse shadow registers and kick the Sentinel active bit.
 * This active bit must be kicked at least once every day (24 hours).
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_ping(s3mu_t *mu);

/**
 * ele_get_fw_version() - Get ELE FW Version
 * @mu: MU peripheral base address
 * @ele_fw_version: Pointer where ElE firmware version will be stored
 *
 * This function is used to retrieve the Sentinel FW version.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_get_fw_version(s3mu_t *mu, uint32_t *ele_fw_version);

/**
 * ele_get_fw_status() - Get ELE FW Status
 * @mu: MU peripheral base address
 * @ele_fw_status: Pointer where ElE firmware status will be stored
 *
 * This function is used to retrieve the Sentinel FW status.
 * If value in ele_fw_status is 0 there is no loaded ELE FW,
 * if 1 ELE FW is authenticated and operational.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_get_fw_status(s3mu_t *mu, uint32_t *ele_fw_status);

/**
 * ele_enable_apc() - Enable APC (Application core)
 * @mu: MU peripheral base address
 *
 * This function is used by RTC (real time core) to release APC (Application core) when needed.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_enable_apc(s3mu_t *mu);

/**
 * ele_forward_lifecycle() - Forward Lifecycle update
 * @mu: MU peripheral base address
 * @lifecycle: Lifecycle to switch
 *
 * This function is to change chip lifecycle
 *  0x01U for NXP provisoned
 *  0x02U for OEM Open
 *  0x08U for OEM Closed
 *  0x80U for OEM Locked
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_forward_lifecycle(s3mu_t *mu, uint32_t lifecycle);

/**
 * ele_read_fuse() - Read common fuse
 * @mu: MU peripheral base address
 * @fuse_id: ID of fuse to be read
 * @fuse: Pointer where the value of the read fuse is stored
 *
 * This function is used to read non-security fuses that are not available through the FSB module
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_read_fuse(s3mu_t *mu, uint32_t fuse_id, uint32_t *fuse);

/**
 * ele_release_rdc() - Release RDC
 * @mu: MU peripheral base address
 * @rdc_id: Resource Domain Control identifier
 * @core_id: Core identifier
 *
 * This function is used to release specified RDC to the core identified in this function.
 * The RDC will be released only if the FW of the core to which is the RDC ownership is going to be
 * transferred has been properly authenticated and verified.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_release_rdc(s3mu_t *mu, uint32_t rdc_id, uint32_t core_id);

/**
 * ele_write_fuse() - Write fuse
 * @mu: MU peripheral base address
 * @bit_position: Fuse identifier expressed as its position in bit in the fuse map.
 * @bit_length: Number of bits to be written
 * @payload: Data to be written in fuse
 * @lock: Write lock requirement, when set to 1 fuse words are locked,
 *        when set to 0 no write lock done.
 * @processed_idx: Pointer where the index of last proccesed fuse is stored.
 *                 Value is valid if !=0xffff
 *
 * This function is used to write fuses.
 * Example bit granularity - write bit 5 and 7 of fuse word index 10.
 * bit_position = 10*32+5 = 0x145. bit_length = 3.
 * payload is 0b101 = 0x5 . Example word granularity - write fuse word index 10.
 * bit_position = 10*32 = 0x140. bit_length = 32 = 0x60. payload 0xWord1.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_write_fuse(s3mu_t *mu, uint32_t bit_position, uint32_t bit_length,
			uint32_t payload, bool lock, uint32_t *processed_idx);

/**
 * ele_get_info() - Get info
 * @mu: MU peripheral base address
 * @response_data: Pointer to output buffer where response data will be writen,
 *                 user must ensure at least 256 bytes available
 *
 * This command is used to get various information from ELE.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_get_info(s3mu_t *mu, uint8_t *response_data);

/**
 * ele_enable_otfad() - Enable an instance of OTFAD.
 * @mu: MU peripheral base address
 * @otfad_id: ID of the OTFAD instance to enable - used only if there are
 *           multiple instances on the SoC
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_enable_otfad(s3mu_t *mu, uint8_t otfad_id);

/**
 * ele_clock_change_start() - Start the clock change process
 * @mu: MU peripheral base address
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_clock_change_start(s3mu_t *mu);

/**
 * ele_clock_change_finish() - Change ELE and/or CM33 clock
 * @mu: MU peripheral base address
 * @new_clock_rate_ele: The new clock rate for ELE
 * @new_clock_rate_cm33: The new clock rate for the CM33 core
 *
 * It is valid to pass both parameters at the same time if the SoC supports both.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_clock_change_finish(s3mu_t *mu, uint8_t new_clock_rate_ele,
				 uint8_t new_clock_rate_cm33);

#endif /* __ELE_CRYPTO_H__ */
