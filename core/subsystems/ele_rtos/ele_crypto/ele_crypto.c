// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_crypto.h"
#include "ele_crypto_internal.h"

#include "utils_ex.h"

#define MAX_GET_INFO_SIZE 256u

status_t ele_load_fw(s3mu_t *mu, const uint8_t *fw, size_t fw_size)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[LOAD_FW_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uintptr_t fw_phys = 0u;
	void *fw_addr = smw_utils_shared_memory_alloc(fw, fw_size, &fw_phys);

	if (!fw_addr)
		return STATUS_FAIL;

	/****************** Load EdgeLock FW message ***********************/
	tmsg[0] = LOAD_FW; /* LOAD_FW Command Header */
	if (SET_OVERFLOW(fw_phys, tmsg[1]) || SET_OVERFLOW(fw_phys, tmsg[3])) {
		status = STATUS_FAIL;
		goto end;
	}

	tmsg[2] = 0x0u; /* Reserved */
	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, LOAD_FW_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == LOAD_FW_RESPONSE_HDR &&
	    rmsg[1] == LOAD_FW_RESPONSE_SUCCESS)
		status = STATUS_SUCCESS;
	else
		status = STATUS_FAIL;

end:
	if (fw_addr)
		smw_utils_shared_memory_free(fw_addr, fw_size, NULL);

	return status;
}

status_t ele_init_services(s3mu_t *mu)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[INIT_SERVICES_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = INIT_SERVICES; /* INIT Command Header */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, INIT_SERVICES_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == INIT_SERVICES_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_open_session(s3mu_t *mu, uint32_t *session_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[OPEN_SESSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = OPEN_SESSION; /* OPEN_SESSION Command Header */
	tmsg[1] = 0x02000001u;	/* EdgeLock ID */
	tmsg[2] = 0x00000000u;	/* Operating mode | Priority */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, OPEN_SESSION_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == OPEN_SESSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read Session ID data */
		*session_id = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_close_session(s3mu_t *mu, uint32_t session_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[CLOSE_SESSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = CLOSE_SESSION; /* CLOSE_SESSION Command Header */
	tmsg[1] = session_id;	 /* Session ID */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, CLOSE_SESSION_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOSE_SESSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_ping(s3mu_t *mu)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[PING_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** PING ELE message ***********************/
	tmsg[0] = PING; /* PING Command Header */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, PING_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == PING_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_get_fw_version(s3mu_t *mu, uint32_t *ele_fw_version)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[GET_FW_VERSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Get firmware version ELE message ***********************/
	tmsg[0] = GET_FW_VERSION; /* Get firmware version Command Header */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_FW_VERSION_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_FW_VERSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read FW version */
		*ele_fw_version = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_get_fw_status(s3mu_t *mu, uint32_t *ele_fw_status)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[GET_FW_STATUS_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Get firmware status ELE message ***********************/
	tmsg[0] = GET_FW_STATUS; /* Get firmware status Command Header */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_FW_STATUS_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_FW_STATUS_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read FW status */
		*ele_fw_status = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_enable_apc(s3mu_t *mu)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[ENABLE_APC_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Enable APC ELE message ***********************/
	tmsg[0] = ENABLE_APC; /* Enable APC Command Header */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, ENABLE_APC_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == ENABLE_APC_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_forward_lifecycle(s3mu_t *mu, uint32_t lifecycle)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[FORWARD_LIFECYCLE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Forward lifecycle ELE message ***********************/
	tmsg[0] = FORWARD_LIFECYCLE; /* Forward lifecycle Command Header */
	tmsg[1] = lifecycle;	     /* Lifecycle to switch to */
	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, FORWARD_LIFECYCLE_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == FORWARD_LIFECYCLE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_read_fuse(s3mu_t *mu, uint32_t fuse_id, uint32_t *fuse)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[READ_FUSE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Read fuse ELE message ***********************/
	tmsg[0] = READ_FUSE; /* Read fuse Command Header */
	tmsg[1] = fuse_id;   /* FuseID to be readed */
	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, READ_FUSE_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == READ_FUSE_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS) {
		/* read fuse */
		*fuse = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_release_rdc(s3mu_t *mu, uint32_t rdc_id, uint32_t core_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[RELEASE_RDC_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Release RDC ELE message ***********************/
	tmsg[0] = RELEASE_RDC;		       /* Release RDC Command Header */
	tmsg[1] = rdc_id << SHIFT_8 | core_id; /* RDC_ID | CoreID */
	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, RELEASE_RDC_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == RELEASE_RDC_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_write_fuse(s3mu_t *mu, uint32_t bit_position, uint32_t bit_length,
			uint32_t payload, bool lock, uint32_t *processed_idx)
{
	status_t status = STATUS_SUCCESS;
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
	tmsg[0] = WRITE_FUSE; /* Write fuse Command Header */
	tmsg[1] = fuse_val; /* Specify fuse and how many bits will be written */
	tmsg[2] = payload;  /* Payload */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, WRITE_FUSE_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == WRITE_FUSE_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS) {
		/* read last processed fuse index */
		/* Value is valid if ! 0xffff*/
		*processed_idx = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_get_info(s3mu_t *mu, uint8_t *response_data)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[GET_INFO_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	size_t response_size = MAX_GET_INFO_SIZE;
	uintptr_t responsedata_phys = 0u;
	void *responsedata_addr =
		smw_utils_shared_memory_alloc(response_data, response_size,
					      &responsedata_phys);

	if (!responsedata_addr)
		return status;

	/****************** Get info message ***********************/
	tmsg[0] = GET_INFO; /* Get info message Command Header */
	tmsg[1] = 0x0u;
	if (SET_OVERFLOW(responsedata_phys, tmsg[2]) ||
	    SET_OVERFLOW(response_size, tmsg[3]))
		goto end;

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_INFO_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_INFO_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS) {
		smw_utils_dcache_invalidate(response_data, MAX_GET_INFO_SIZE);
		status = STATUS_SUCCESS;
	} else {
		status = STATUS_FAIL;
	}

end:
	smw_utils_shared_memory_free(responsedata_addr, response_size,
				     response_data);
	return status;
}

status_t ele_enable_otfad(s3mu_t *mu, uint8_t otfad_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[ENABLE_OTFAD_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Enable OTFAD message ***********************/
	tmsg[0] = ENABLE_OTFAD; /* Enable OTFAD message Command Header */
#if defined(FSL_FEATURE_SOC_OTFAD_COUNT) && (FSL_FEATURE_SOC_OTFAD_COUNT > 1)
	tmsg[1] = (uint32_t)otfad_id; /* ID of the OTFAD instance */
#else
	(void)otfad_id; /* Prevent an unused variable warning */
#endif

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, ENABLE_OTFAD_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == ENABLE_OTFAD_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_clock_change_start(s3mu_t *mu)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[CLOCK_CHANGE_START_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Clock change start message ***********************/
	tmsg[0] = CLOCK_CHANGE_START; /* Clock Change Start Command Header */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, CLOCK_CHANGE_START_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOCK_CHANGE_START_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_clock_change_finish(s3mu_t *mu, uint8_t new_clock_rate_ele,
				 uint8_t new_clock_rate_cm33)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[CLOCK_CHANGE_FINISH_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Clock change finish message ***********************/
	tmsg[0] = CLOCK_CHANGE_FINISH; /* Clock Change Finish Command Header */
	tmsg[1] =
		(uint32_t)new_clock_rate_cm33 << SHIFT_16 |
		(uint32_t)new_clock_rate_ele; /* New CM33 and ELE clock rates */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, CLOCK_CHANGE_FINISH_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOCK_CHANGE_FINISH_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}
