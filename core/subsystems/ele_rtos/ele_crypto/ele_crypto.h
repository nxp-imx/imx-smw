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
 * @fw: in system memory where FW can be found
 * @fw_size: size of the FW in bytes
 *
 * This function Loads firmware into EdgeLock Enclave.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
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
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_init_services(s3mu_t *mu);

/**
 * ele_open_session() - Open ELE Session
 * @mu: MU peripheral base address
 * @sessionID: pointer to output unique session ID word
 *
 * This function opens Session for EdgeLock Enclave.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_open_session(s3mu_t *mu, uint32_t *sessionID);

/**
 * ele_close_session() - Close ELE Session
 * @mu: MU peripheral base address
 * @sessionID: unique session ID obtained by calling ele_open_session()
 *
 * This function closes the Session for EdgeLock Enclave.
 *
 * Return:
 * kStatus_Success - Success
 * kStatus_Fail    - Fail
 */
status_t ele_close_session(s3mu_t *mu, uint32_t sessionID);

/**
 * ele_ping() - Ping ELE
 * @mu: MU peripheral base address
 *
 * This function Ping EdgeLock Enclave, can be sent at any time to verify ELE is alive.
 * Additionally, this command reloads the fuse shadow registers and kick the Sentinel active bit.
 * This active bit must be kicked at least once every day (24 hours).
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_ping(s3mu_t *mu);

/**
 * ele_get_fw_version() - Get ELE FW Version
 * @mu: MU peripheral base address
 * @EleFwVersion: Pointer where ElE firmware version will be stored
 *
 * This function is used to retrieve the Sentinel FW version.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_get_fw_version(s3mu_t *mu, uint32_t *EleFwVersion);

/**
 * ele_get_fw_status() - Get ELE FW Status
 * @mu: MU peripheral base address
 * @EleFwStatus: Pointer where ElE firmware status will be stored
 *
 * This function is used to retrieve the Sentinel FW status.
 * If value in EleFwStatus is 0 there is no loaded ELE FW,
 * if 1 ELE FW is authenticated and operational.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_get_fw_status(s3mu_t *mu, uint32_t *EleFwStatus);

/**
 * ele_enable_apc() - Enable APC (Application core)
 * @mu: MU peripheral base address
 *
 * This function is used by RTC (real time core) to release APC (Application core) when needed.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_enable_apc(s3mu_t *mu);

/**
 * ele_forward_lifecycle() - Forward Lifecycle update
 * @mu: MU peripheral base address
 * @Lifecycle: Lifecycle to switch
 *
 * This function is to change chip lifecycle
 *  0x01U for NXP provisoned
 *  0x02U for OEM Open
 *  0x08U for OEM Closed
 *  0x80U for OEM Locked
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_forward_lifecycle(s3mu_t *mu, uint32_t Lifecycle);

/**
 * ele_read_fuse() - Read common fuse
 * @mu: MU peripheral base address
 * @FuseID: ID of fuse to be read
 * @Fuse: Pointer where the value of the read fuse is stored
 *
 * This function is used to read non-security fuses that are not available through the FSB module.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_read_fuse(s3mu_t *mu, uint32_t FuseID, uint32_t *Fuse);

/**
 * ele_release_rdc() - Release RDC
 * @mu: MU peripheral base address
 * @RdcID: Resource Domain Control identifier
 * @CoreID: Core identifier
 *
 * This function is used to release specified RDC to the core identified in this function.
 * The RDC will be released only if the FW of the core to which is the RDC ownership is going to be
 * transferred has been properly authenticated and verified.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_release_rdc(s3mu_t *mu, uint32_t RdcID, uint32_t CoreID);

/**
 * ele_write_fuse() - Write fuse
 * @mu: MU peripheral base address
 * @BitPosition: Fuse identifier expressed as its position in bit in the fuse map.
 * @BitLength: Number of bits to be written
 * @Payload: Data to be written in fuse
 * @lock: Write lock requirement, when set to 1 fuse words are locked,
 *        when set to 0 no write lock done.
 * @Processed_idx: Pointer where the index of last proccesed fuse is stored.
 *                 Value is valid if !=0xffff
 *
 * This function is used to write fuses.
 * Example bit granularity - write bit 5 and 7 of fuse word index 10.
 * BitPosition = 10*32+5 = 0x145. BitLength = 3.
 * Payload is 0b101 = 0x5 . Example word granularity - write fuse word index 10.
 * BitPosition = 10*32 = 0x140. BitLength = 32 = 0x60. Payload 0xWord1.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_write_fuse(s3mu_t *mu, uint32_t BitPosition, uint32_t BitLength,
			uint32_t Payload, bool lock, uint32_t *Processed_idx);

/**
 * ele_get_info() - Get info
 * @mu: MU peripheral base address
 * @ResponseData: pointer to output buffer where response data will be writen,
 *                user must ensure at least 160 bytes available
 *
 * This command is used to get various information from ELE.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_get_info(s3mu_t *mu, uint8_t *ResponseData);

/**
 * ele_enable_otfad() - Enable an instance of OTFAD.
 * @mu: MU peripheral base address
 * @OtfadID: ID of the OTFAD instance to enable - used only if there are
 *           multiple instances on the SoC
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_enable_otfad(s3mu_t *mu, uint8_t OtfadID);

/**
 * ele_clock_change_start() - Start the clock change process
 * @mu: MU peripheral base address
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_clock_change_start(s3mu_t *mu);

/**
 * ele_clock_change_finish() - Change ELE and/or CM33 clock
 * @mu: MU peripheral base address
 * @NewClockRateELE: the new clock rate for ELE
 * @NewClockRateCM33: the new clock rate for the CM33 core
 *
 * It is valid to pass both parameters at the same time if the SoC supports both.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_clock_change_finish(s3mu_t *mu, uint8_t NewClockRateELE,
				 uint8_t NewClockRateCM33);

#endif /* __ELE_CRYPTO_H__ */
