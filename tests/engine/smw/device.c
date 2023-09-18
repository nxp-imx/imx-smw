// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include <stdlib.h>

#include <smw_device.h>

#include "device.h"
#include "util.h"

/**
 * set_lifecycle_bad_args() - Set device lifecycle bad parameters function
 *                            of the test error.
 * @subtest: Subtest data
 * @args: SMW device lifecycle parameters.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_lifecycle_bad_args(struct subtest_data *subtest,
				  struct smw_device_lifecycle_args **args)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!subtest || !args)
		return ERR_CODE(BAD_ARGS);

	ret = util_read_test_error(&error, subtest->params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
		break;
	}

	return ret;
}

int device_uuid(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_device_uuid_args args = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	/* First get the uuid size */
	subtest->smw_status = smw_device_get_uuid(&args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (!args.uuid_length) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	args.uuid = calloc(1, args.uuid_length);
	if (!args.uuid) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	subtest->smw_status = smw_device_get_uuid(&args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	DBG_DHEX("Device UUID", args.uuid, args.uuid_length);

	res = ERR_CODE(PASSED);

end:
	if (args.uuid)
		free(args.uuid);

	return res;
}

int device_attestation(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct certificate_common {
		uint8_t cmd;
		uint8_t version;
		uint16_t length;
		uint16_t soc_id;
		uint16_t soc_rev;
		uint16_t lifecycle;
		uint8_t ssm_state;
		uint8_t reserved;
		uint32_t uid[4];
		uint8_t sha_rom_patch[32];
		uint8_t sha_fw[32];
	} *certificate = NULL;

	unsigned int challenge = 0xCAFEF00D;
	struct smw_device_attestation_args args = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	/* First get the certificate size */
	subtest->smw_status = smw_device_attestation(&args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (!args.certificate_length) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	args.challenge = (unsigned char *)&challenge;
	args.challenge_length = sizeof(challenge);

	args.certificate = calloc(1, args.certificate_length);
	if (!args.certificate) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	subtest->smw_status = smw_device_attestation(&args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	DBG_DHEX("Certificate", args.certificate, args.certificate_length);

	certificate = (struct certificate_common *)args.certificate;
	DBG_PRINT("Certificate:\n"
		  " cmd: 0x%X\n"
		  " version: 0x%X\n"
		  " length: %d\n"
		  " soc_rev: 0x%04X\n"
		  " soc_id: 0x%04X\n"
		  " ssm_state: 0x%02X\n"
		  " lifecycle: 0x%04X\n"
		  " UUID: 0x%08X 0x%08X 0x%08X 0x%08X",
		  certificate->cmd, certificate->version, certificate->length,
		  certificate->soc_rev, certificate->soc_id,
		  certificate->ssm_state, certificate->lifecycle,
		  certificate->uid[0], certificate->uid[1], certificate->uid[2],
		  certificate->uid[3]);

	res = ERR_CODE(PASSED);

end:
	if (args.certificate)
		free(args.certificate);

	return res;
}

int device_lifecycle(struct subtest_data *subtest, bool set)
{
	int res = ERR_CODE(BAD_ARGS);
	struct smw_device_lifecycle_args args = { 0 };
	struct smw_device_lifecycle_args *smw_args = &args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	if (!subtest->subsystem || !strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	args.version = subtest->version;

	/* Specific test cases */
	res = set_lifecycle_bad_args(subtest, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (set) {
		res = util_read_json_type(&args.lifecycle_name, LIFECYCLE_OBJ,
					  t_string, subtest->params);
		if (res != ERR_CODE(PASSED))
			goto exit;

		/*
		 * If the test define a lifecycle `CURRENT` read the device
		 * lifecycle and set the same.
		 */
		if (args.lifecycle_name &&
		    !strcmp(args.lifecycle_name, "CURRENT")) {
			subtest->smw_status =
				smw_device_get_lifecycle(smw_args);
			if (subtest->smw_status != SMW_STATUS_OK) {
				res = ERR_CODE(API_STATUS_NOK);
				goto exit;
			}
		}

		subtest->smw_status = smw_device_set_lifecycle(smw_args);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(API_STATUS_NOK);
			goto exit;
		}
	} else {
		subtest->smw_status = smw_device_get_lifecycle(smw_args);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(API_STATUS_NOK);
			goto exit;
		}

		DBG_PRINT("Device Lifecycle is %s", smw_args->lifecycle_name);
	}

exit:
	return res;
}
