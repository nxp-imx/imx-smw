// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include <stdlib.h>

#include <smw_device.h>

#include "device.h"
#include "util.h"
#include "util_certificate.h"

/**
 * set_device_uuid_bad_args() - Set device UUID bad parameters function
 *                              of the test error.
 * @subtest: Subtest data
 * @args: SMW device UUID parameters.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_device_uuid_bad_args(struct subtest_data *subtest,
				    struct smw_device_uuid_args **args)
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

/**
 * set_attestation_bad_args() - Set device attestation bad parameters function
 *                              of the test error.
 * @subtest: Subtest data
 * @args: SMW device attestation parameters.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_attestation_bad_args(struct subtest_data *subtest,
				    struct smw_device_attestation_args **args)
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
	struct smw_device_uuid_args *smw_args = &args;
	struct tbuffer uuid = { 0 };
	struct tbuffer certificate = { 0 };
	int cert_id = INT_MAX;
	bool uuid_output_present = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (!subtest->subsystem || !strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	res = util_read_json_type(&uuid, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (res == ERR_CODE(PASSED))
		uuid_output_present = true;

	res = set_device_uuid_bad_args(subtest, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = util_read_json_type(&certificate, CERTIFICATE_OBJ, t_buffer_hex,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		args.certificate = certificate.data;
		args.certificate_length = certificate.length;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto end;
	}

	/* Get 'cert_id' parameter */
	res = util_read_json_type(&cert_id, CERTIFICATE_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (cert_id != INT_MAX) {
		res = util_certificate_find_node(list_certificates(subtest),
						 cert_id, &args.certificate,
						 &args.certificate_length);
	}

	if (!uuid.length && !uuid_output_present) {
		/* JSON test file doesn't give the UUID length */
		subtest->smw_status = smw_device_get_uuid(smw_args);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}

		if (!args.uuid_length) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}
	} else {
		args.uuid_length = uuid.length;
	}

	if (args.uuid_length) {
		args.uuid = calloc(1, args.uuid_length);
		if (!args.uuid) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}
	}

	subtest->smw_status = smw_device_get_uuid(smw_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (uuid.data)
		res = util_compare_buffers(args.uuid, args.uuid_length,
					   uuid.data, uuid.length);
	else
		res = ERR_CODE(PASSED);

	DBG_DHEX("Device UUID", args.uuid, args.uuid_length);

end:
	if (args.uuid)
		free(args.uuid);

	if (uuid.data)
		free(uuid.data);

	if (certificate.data)
		free(certificate.data);

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
	} *cert_head = NULL;

	struct smw_device_attestation_args args = { 0 };
	struct smw_device_attestation_args *smw_args = &args;
	struct tbuffer certificate = { 0 };
	struct tbuffer challenge = { 0 };
	int cert_id = INT_MAX;
	bool cert_output_present = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (!subtest->subsystem || !strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	res = util_read_json_type(&certificate, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res == ERR_CODE(PASSED))
		cert_output_present = true;
	else if (res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = util_read_json_type(&challenge, CHALLENGE_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	/* Get 'cert_id' parameter */
	res = util_read_json_type(&cert_id, CERTIFICATE_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = set_attestation_bad_args(subtest, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (!certificate.length && !cert_output_present) {
		/* JSON test file doesn't give the UUID length */
		subtest->smw_status = smw_device_attestation(smw_args);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}

		if (!args.certificate_length) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}
	} else {
		args.certificate_length = certificate.length;
	}

	args.challenge = challenge.data;
	args.challenge_length = challenge.length;

	if (args.certificate_length) {
		args.certificate = calloc(1, args.certificate_length);
		if (!args.certificate) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}
	}

	subtest->smw_status = smw_device_attestation(smw_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (!args.certificate)
		goto end;

	if (certificate.data)
		res = util_compare_buffers(args.certificate,
					   args.certificate_length,
					   certificate.data,
					   certificate.length);

	DBG_DHEX("Certificate", args.certificate, args.certificate_length);

	cert_head = (struct certificate_common *)args.certificate;
	DBG_PRINT("Certificate:\n"
		  " cmd: 0x%X\n"
		  " version: 0x%X\n"
		  " length: %d\n"
		  " soc_rev: 0x%04X\n"
		  " soc_id: 0x%04X\n"
		  " ssm_state: 0x%02X\n"
		  " lifecycle: 0x%04X\n"
		  " UUID: 0x%08X 0x%08X 0x%08X 0x%08X",
		  cert_head->cmd, cert_head->version, cert_head->length,
		  cert_head->soc_rev, cert_head->soc_id, cert_head->ssm_state,
		  cert_head->lifecycle, cert_head->uid[0], cert_head->uid[1],
		  cert_head->uid[2], cert_head->uid[3]);

	if (cert_id != INT_MAX) {
		/* Store certificate */
		res = util_certificate_add_node(list_certificates(subtest),
						cert_id, args.certificate,
						args.certificate_length);
		if (res == ERR_CODE(PASSED))
			args.certificate = NULL;
	} else {
		res = ERR_CODE(PASSED);
	}

end:
	if (args.certificate)
		free(args.certificate);

	if (challenge.data)
		free(challenge.data);

	if (certificate.data)
		free(certificate.data);

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
