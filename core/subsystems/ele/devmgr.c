// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "debug.h"
#include "devmgr.h"
#include "utils.h"

#include "common.h"

#define ELE_NB_UID_WORD 4
#define ELE_UID_SIZE	(ELE_NB_UID_WORD * sizeof(uint32_t))
struct ele_get_info_head {
	uint16_t soc_rev;
	uint16_t soc_id;
	uint16_t lifecycle;
	uint8_t ssm_state;
	uint8_t reserved;
	uint32_t nonce;
	uint32_t uid[ELE_NB_UID_WORD];
};

static int device_attestation_operation(struct hdl *hdl,
					op_dev_attest_args_t *op_args)
{
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;
	hsm_err_t err = HSM_FEATURE_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_dev_attest(hdl->session, op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_dev_attest returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Check if all buffers allocated by the ELE Library are valid */
	if (!op_args->uid || !op_args->uid_sz || !op_args->sha_rom_patch ||
	    !op_args->rom_patch_sha_sz || !op_args->sha_fw ||
	    !op_args->sha_fw_sz || !op_args->signature || !op_args->sign_sz)
		status = SMW_STATUS_SUBSYSTEM_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int device_attestation(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *nonce = NULL;
	unsigned char *certificate = NULL;
	unsigned int nonce_length = 0;
	unsigned int certificate_length = 0;

	op_dev_attest_args_t op_args = { 0 };

	struct ele_get_info_head *cert_head = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	nonce = smw_devmgr_get_challenge_data(args);
	nonce_length = smw_devmgr_get_challenge_length(args);
	certificate = smw_devmgr_get_certificate_data(args);

	if (certificate && (!nonce || !nonce_length))
		goto end;

	if (nonce && nonce_length)
		SMW_UTILS_MEMCPY((void *)&op_args.nounce, nonce,
				 MIN(nonce_length, sizeof(op_args.nounce)));

	status = device_attestation_operation(hdl, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	if (op_args.uid_sz != ELE_UID_SIZE) {
		SMW_DBG_PRINTF(ERROR,
			       "Wrong Device UID size got %d expected %d",
			       op_args.uid_sz, ELE_UID_SIZE);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	certificate_length = sizeof(*cert_head);
	certificate_length += op_args.rom_patch_sha_sz;
	certificate_length += op_args.sha_fw_sz;
	certificate_length += op_args.sign_sz;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_dev_attest() length = %d\n"
		       "    soc_id   : 0x%04X\n"
		       "    soc_rev  : 0x%04X\n"
		       "    ssm state: 0x%02X\n"
		       "    lifecycle: 0x%04X\n"
		       "    nonce    : 0x%08X\n",
		       __func__, __LINE__, certificate_length, op_args.soc_id,
		       op_args.soc_rev, op_args.ssm_state, op_args.lmda_val,
		       op_args.rsp_nounce);

	SMW_DBG_PRINTF(VERBOSE, "Device UID (%d bytes)", op_args.uid_sz);
	SMW_DBG_HEX_DUMP(VERBOSE, op_args.uid, op_args.uid_sz, 4);

	SMW_DBG_PRINTF(VERBOSE, "ROM Patch sha (%d bytes)",
		       op_args.rom_patch_sha_sz);
	SMW_DBG_HEX_DUMP(VERBOSE, op_args.sha_rom_patch,
			 op_args.rom_patch_sha_sz, 4);

	SMW_DBG_PRINTF(VERBOSE, "FW sha (%d bytes)", op_args.sha_fw_sz);
	SMW_DBG_HEX_DUMP(VERBOSE, op_args.sha_fw, op_args.sha_fw_sz, 4);

	SMW_DBG_PRINTF(VERBOSE, "Certificate signature (%d bytes)",
		       op_args.sign_sz);
	SMW_DBG_HEX_DUMP(VERBOSE, op_args.signature, op_args.sign_sz, 4);

	/*
	 * If the certificate is NULL, user queries the certificate
	 * length expected.
	 * Else, checks if the certificate length is big enough to
	 * contain the certificate.
	 */
	if (certificate) {
		if (smw_devmgr_get_certificate_length(args) >=
		    certificate_length) {
			cert_head = (struct ele_get_info_head *)certificate;
			cert_head->soc_id = op_args.soc_id;
			cert_head->soc_rev = op_args.soc_rev;
			cert_head->lifecycle = op_args.lmda_val;
			cert_head->ssm_state = op_args.ssm_state;
			cert_head->nonce = op_args.nounce;

			SMW_UTILS_MEMCPY(cert_head->uid, op_args.uid,
					 op_args.uid_sz);
			certificate += sizeof(*cert_head);

			SMW_UTILS_MEMCPY(certificate, op_args.sha_rom_patch,
					 op_args.rom_patch_sha_sz);
			certificate += op_args.rom_patch_sha_sz;

			SMW_UTILS_MEMCPY(certificate, op_args.sha_fw,
					 op_args.sha_fw_sz);
			certificate += op_args.sha_fw_sz;

			SMW_UTILS_MEMCPY(certificate, op_args.signature,
					 op_args.sign_sz);
		} else {
			status = SMW_STATUS_OUTPUT_TOO_SHORT;
		}
	}

	smw_devmgr_set_certificate_length(args, certificate_length);

end:
	/* Free all buffers allocated by the ELE Library */
	if (op_args.uid)
		SMW_UTILS_FREE(op_args.uid);
	if (op_args.sha_rom_patch)
		SMW_UTILS_FREE(op_args.sha_rom_patch);
	if (op_args.sha_fw)
		SMW_UTILS_FREE(op_args.sha_fw);
	if (op_args.signature)
		SMW_UTILS_FREE(op_args.signature);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int device_uuid(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *uuid = NULL;
	unsigned int uuid_length = 0;
	unsigned char *certificate = NULL;
	unsigned int certificate_length = 0;
	unsigned int *device_uid = NULL;

	op_dev_attest_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	uuid = smw_devmgr_get_uuid_data(args);
	uuid_length = smw_devmgr_get_uuid_length(args);

	if (!uuid || uuid_length < ELE_UID_SIZE) {
		smw_devmgr_set_uuid_length(args, ELE_UID_SIZE);

		if (uuid && uuid_length < ELE_UID_SIZE)
			status = SMW_STATUS_OUTPUT_TOO_SHORT;
		else
			status = SMW_STATUS_OK;

		goto end;
	}

	certificate = smw_devmgr_get_certificate_data(args);
	certificate_length = smw_devmgr_get_certificate_length(args);

	if (!certificate) {
		status = device_attestation_operation(hdl, &op_args);
		if (status != SMW_STATUS_OK)
			goto end;

		device_uid = (unsigned int *)op_args.uid;
	} else if (certificate_length >= sizeof(struct ele_get_info_head)) {
		device_uid = ((struct ele_get_info_head *)certificate)->uid;
	} else {
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		smw_devmgr_set_uuid_length(args, ELE_UID_SIZE);
		goto end;
	}

	for (int i = 0; i < ELE_NB_UID_WORD; i++, uuid += sizeof(*device_uid))
		SMW_UTILS_MEMCPY(uuid, &device_uid[i], sizeof(*device_uid));

	smw_devmgr_set_uuid_length(args, ELE_UID_SIZE);
	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

bool ele_device_handle(struct hdl *hdl, enum operation_id operation_id,
		       void *args, int *status)
{
	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_DEVICE_ATTESTATION:
		*status = device_attestation(hdl, args);
		break;

	case OPERATION_ID_DEVICE_GET_UUID:
		*status = device_uuid(hdl, args);
		break;

	default:
		return false;
	}

	return true;
}
