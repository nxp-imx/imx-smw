// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_crypto.h"
#include "ele_crypto_internal.h"

#include "utils_ex.h"

#define MAX_GET_INFO_SIZE 256u

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
status_t ele_load_fw(s3mu_t *mu, const uint8_t *fw, size_t fw_size)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[LOAD_FW_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uintptr_t fw_phys = 0u;
	void *fw_addr = smw_utils_shared_memory_alloc(fw, fw_size, &fw_phys);

	if (!fw_addr)
		return kStatus_Fail;

	/****************** Load EdgeLock FW message ***********************/
	tmsg[0] = LOAD_FW; // LOAD_FW Command Header
	tmsg[1] = fw_phys; // EdgeLock FW address
	tmsg[2] = 0x0u;	   // Reserved
	tmsg[3] = fw_phys; // EdgeLock FW address

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, LOAD_FW_SIZE);
	if (status != kStatus_Success)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == LOAD_FW_RESPONSE_HDR &&
	    rmsg[1] == LOAD_FW_RESPONSE_SUCCESS)
		status = kStatus_Success;
	else
		status = kStatus_Fail;

end:
	if (fw_addr)
		smw_utils_shared_memory_free(fw_addr, fw_size, NULL);

	return status;
}

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
status_t ele_init_services(s3mu_t *mu)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[INIT_SERVICES_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = INIT_SERVICES; // INIT Command Header

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, INIT_SERVICES_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == INIT_SERVICES_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

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
status_t ele_open_session(s3mu_t *mu, uint32_t *sessionID)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[OPEN_SESSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = OPEN_SESSION; // OPEN_SESSION Command Header
	tmsg[1] = 0x02000001u;	// EdgeLock ID
	tmsg[2] = 0x00000000u;	// Operating mode | Priority

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, OPEN_SESSION_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == OPEN_SESSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read Session ID data */
		*sessionID = rmsg[2];
		return kStatus_Success;
	}

	return kStatus_Fail;
}

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
status_t ele_close_session(s3mu_t *mu, uint32_t sessionID)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[CLOSE_SESSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = CLOSE_SESSION; // CLOSE_SESSION Command Header
	tmsg[1] = sessionID;	 // Session ID

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, CLOSE_SESSION_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOSE_SESSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

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
status_t ele_ping(s3mu_t *mu)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[PING_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** PING ELE message ***********************/
	tmsg[0] = PING; // PING Command Header

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, PING_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == PING_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

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
status_t ele_get_fw_version(s3mu_t *mu, uint32_t *EleFwVersion)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[GET_FW_VERSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Get firmware version ELE message ***********************/
	tmsg[0] = GET_FW_VERSION; // Get firmware version Command Header

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_FW_VERSION_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_FW_VERSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read FW version */
		*EleFwVersion = rmsg[2];
		return kStatus_Success;
	}

	return kStatus_Fail;
}

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
status_t ele_get_fw_status(s3mu_t *mu, uint32_t *EleFwStatus)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[GET_FW_STATUS_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Get firmware status ELE message ***********************/
	tmsg[0] = GET_FW_STATUS; // Get firmware status Command Header

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_FW_STATUS_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_FW_STATUS_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read FW status */
		*EleFwStatus = rmsg[2];
		return kStatus_Success;
	}

	return kStatus_Fail;
}

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
status_t ele_enable_apc(s3mu_t *mu)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[ENABLE_APC_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Enable APC ELE message ***********************/
	tmsg[0] = ENABLE_APC; // Enable APC Command Header

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, ENABLE_APC_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == ENABLE_APC_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

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
status_t ele_forward_lifecycle(s3mu_t *mu, uint32_t Lifecycle)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[FORWARD_LIFECYCLE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Forward lifecycle ELE message ***********************/
	tmsg[0] = FORWARD_LIFECYCLE; // Forward lifecycle Command Header
	tmsg[1] = Lifecycle;	     // Lifecycle to switch to

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, FORWARD_LIFECYCLE_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == FORWARD_LIFECYCLE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

/**
 * ele_read_fuse() - Read common fuse
 * @mu: MU peripheral base address
 * @FuseID: ID of fuse to be read
 * @Fuse: Pointer where the value of the read fuse is stored
 *
 * This function is used to read non-security fuses that are not available through the FSB module
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_read_fuse(s3mu_t *mu, uint32_t FuseID, uint32_t *Fuse)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[READ_FUSE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Read fuse ELE message ***********************/
	tmsg[0] = READ_FUSE; // Read fuse Command Header
	tmsg[1] = FuseID;    // FuseID to be readed

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, READ_FUSE_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == READ_FUSE_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS) {
		/* read fuse */
		*Fuse = rmsg[2];
		return kStatus_Success;
	}

	return kStatus_Fail;
}

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
status_t ele_release_rdc(s3mu_t *mu, uint32_t RdcID, uint32_t CoreID)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[RELEASE_RDC_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Release RDC ELE message ***********************/
	tmsg[0] = RELEASE_RDC;		     // Release RDC Command Header
	tmsg[1] = RdcID << SHIFT_8 | CoreID; // RDC_ID | CoreID

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, RELEASE_RDC_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == RELEASE_RDC_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

status_t ele_write_fuse(s3mu_t *mu, uint32_t bit_position, uint32_t bit_length,
			uint32_t payload, bool lock, uint32_t *processed_idx)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[WRITE_FUSE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/* Create word specifying which fuse and how many bits will be written*/
	/*   +----------------------------------------------------+
	 *   | Lock  |           |  Bit Length  |   Bit position  |
	 *   +---------------------------+------------------------+
	 *   | bit 31| Bit 30-29 |  Bit 29-16   |    Bit 15-0     |
	 *   +----------------------------------------------------+
	 */
	uint32_t fuse_val = (bit_length << BIT_LENGTH_SHIFT) | (bit_position);

	if (lock)
		fuse_val |= 1u << LOCK_SHIFT;

	/****************** Write fuse ELE message ***********************/
	tmsg[0] = WRITE_FUSE; // Write fuse Command Header
	tmsg[1] = fuse_val;   // Specify fuse and how many bits will be written
	tmsg[2] = payload;    // Payload

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, WRITE_FUSE_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == WRITE_FUSE_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS) {
		/* read last processed fuse index */
		/* Value is valid if ! 0xffff*/
		*processed_idx = rmsg[2];
		return kStatus_Success;
	}

	return kStatus_Fail;
}

/**
 * ele_get_info() - Get info
 * @mu: MU peripheral base address
 * @ResponseData: pointer to output buffer where response data will be writen,
 *                user must ensure at least 256 bytes available
 *
 * This command is used to get various information from ELE.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_get_info(s3mu_t *mu, uint8_t *ResponseData)
{
	status_t status = kStatus_Fail;
	uint32_t tmsg[GET_INFO_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	size_t ResponseSize = MAX_GET_INFO_SIZE;
	uintptr_t responsedata_phys = 0u;
	void *responsedata_addr =
		smw_utils_shared_memory_alloc(ResponseData, ResponseSize,
					      &responsedata_phys);

	if (!responsedata_addr)
		return status;

	/****************** Get info message ***********************/
	tmsg[0] = GET_INFO; // Get info message Command Header
	tmsg[1] = 0x0u;
	tmsg[2] = responsedata_phys; // Output buffer
	tmsg[3] = ResponseSize;	     // Size of ResponseData length

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_INFO_SIZE);
	if (status != kStatus_Success)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_INFO_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS) {
		smw_utils_dcache_invalidate(ResponseData, MAX_GET_INFO_SIZE);
		status = kStatus_Success;
	} else {
		status = kStatus_Fail;
	}

end:
	smw_utils_shared_memory_free(responsedata_addr, ResponseSize,
				     ResponseData);
	return status;
}

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
status_t ele_enable_otfad(s3mu_t *mu, uint8_t OtfadID)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[ENABLE_OTFAD_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Enable OTFAD message ***********************/
	tmsg[0] = ENABLE_OTFAD; // Enable OTFAD message Command Header
#if defined(FSL_FEATURE_SOC_OTFAD_COUNT) && (FSL_FEATURE_SOC_OTFAD_COUNT > 1)
	tmsg[1] = (uint32_t)OtfadID; // ID of the OTFAD instance
#else
	(void)OtfadID; /* Prevent an unused variable warning */
#endif

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, ENABLE_OTFAD_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == ENABLE_OTFAD_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

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
status_t ele_clock_change_start(s3mu_t *mu)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[CLOCK_CHANGE_START_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Clock change start message ***********************/
	tmsg[0] = CLOCK_CHANGE_START; // Clock Change Start Command Header

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, CLOCK_CHANGE_START_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOCK_CHANGE_START_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

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
				 uint8_t NewClockRateCM33)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[CLOCK_CHANGE_FINISH_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Clock change finish message ***********************/
	tmsg[0] = CLOCK_CHANGE_FINISH; // Clock Change Finish Command Header
	tmsg[1] = (uint32_t)NewClockRateCM33 << SHIFT_16 |
		  (uint32_t)NewClockRateELE; // New CM33 and ELE clock rates

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, CLOCK_CHANGE_FINISH_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOCK_CHANGE_FINISH_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}
