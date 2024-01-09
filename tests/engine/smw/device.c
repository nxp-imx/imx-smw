// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <smw_device.h>

#include "device.h"
#include "paths.h"
#include "util.h"
#include "util_certificate.h"
#include "util_file.h"

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

/**
 * set_reprovision_bad_args() - Set device reproivisioning bad parameters
 *                              function of the test error.
 * @subtest: Subtest data
 * @args: SMW device reprovisioning parameters.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_reprovision_bad_args(struct subtest_data *subtest,
				    struct smw_device_reprovision_args **args)
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
 * cst_sign - Sign binary with CST tool
 * @work_dir: Working directory
 * @bin_file: Fullpath to the output binary file signed
 * @csf_file: Fullpath to the input CST text file
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL               - Fork operation failure
 * -FAILED                 - System command failed
 */
static int cst_sign(const char *work_dir, char *const bin_file,
		    char *const csf_file)
{
	int ret = ERR_CODE(FAILED);

	char *const cmd[] = { "cst", "-o", bin_file, "-i", csf_file, NULL };
	char cwd[PATH_MAX] = { 0 };

	ret = util_app_find_exe("cst");
	if (ret != ERR_CODE(PASSED)) {
		DBG_PRINT("Executable cst not installed");
		ret = ERR_CODE(SKIPPED);
		goto exit;
	}

	if (getcwd(cwd, sizeof(cwd)) != cwd) {
		DBG_PRINT("Getting cwd error %s", util_get_strerr());
		goto exit;
	}

	if (chdir(work_dir)) {
		DBG_PRINT("chdir (%s) error %s", work_dir, util_get_strerr());
		goto exit;
	}

	ret = util_app_exe_system(cmd);

exit:
	if (strlen(cwd) && chdir(cwd))
		DBG_PRINT("chdir (%s) error %s", cwd, util_get_strerr());

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

int device_reprovision(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct tbuffer msg = { 0 };
	struct smw_device_reprovision_args args = { 0 };
	struct smw_device_reprovision_args *smw_args = &args;
	char template_csf[] = "template_signed_msg.csf";
	char repo_csf[] = "key_reprovisioning.csf";
	char repo_bin[] = "key_reprovisioning.bin";
	char sign_offset[10] = { 0 };
	size_t signed_msg_length = 0;
	DIR *dir = NULL;

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
	res = set_reprovision_bad_args(subtest, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_read_json_type(&msg, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (!msg.length && !msg.data) {
		/* JSON test doesn't define the message reprovisioning length */
		subtest->smw_status = smw_device_reprovision_prepare(smw_args);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(API_STATUS_NOK);
			goto exit;
		}

		if (!args.data_length) {
			res = ERR_CODE(API_STATUS_NOK);
			goto exit;
		}
	} else {
		args.data_length = msg.length;
	}

	if (args.data_length) {
		args.data = malloc(args.data_length);
		if (!args.data) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}
	}

	subtest->smw_status = smw_device_reprovision_prepare(smw_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	DBG_DHEX("Reprovisioning payload", args.data, args.data_length);

	/* Check if the CST keys are installed, else skip the test */
	dir = opendir(CST_KEYS_DIR);
	if (!dir) {
		if (__errno_location() && errno == ENOENT)
			res = ERR_CODE(SKIPPED);
		else
			res = ERR_CODE(FAILED);

		DBG_PRINT("Open directory (%s): %s", CST_KEYS_DIR,
			  util_get_strerr());
		goto exit;
	}

	if (closedir(dir)) {
		DBG_PRINT("Closed directory (%s): %s", CST_KEYS_DIR,
			  util_get_strerr());
		res = ERR_CODE(FAILED);
		goto exit;
	}

	res = util_file_append_buffer(CST_WORKING_DIR, repo_bin, "w",
				      (char *)args.data, args.data_length);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Set the binary file name to sign in the CSF file */
	res = util_file_replace(CST_WORKING_DIR, template_csf, repo_csf,
				"REPLACE_CONTAINER", repo_bin);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Set the offset of the signature in the CSF file */
	if (sprintf(sign_offset, "0x%X", args.data_length) < 0) {
		DBG_PRINT("sprintf error: %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	res = util_file_replace(CST_WORKING_DIR, repo_csf, repo_csf,
				"REPLACE_SIGN_OFFSET", sign_offset);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = cst_sign(CST_WORKING_DIR, repo_bin, repo_csf);
	if (res != ERR_CODE(PASSED))
		goto exit;

	free(args.data);
	args.data = NULL;

	res = util_file_to_buffer(CST_WORKING_DIR, repo_bin,
				  (char **)&args.data, &signed_msg_length);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (SET_OVERFLOW(signed_msg_length, args.data_length)) {
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	subtest->smw_status = smw_device_reprovision(smw_args);
	if (subtest->smw_status != SMW_STATUS_OK &&
	    subtest->smw_status != SMW_STATUS_OEM_SRKH_NOT_FUSED)
		res = ERR_CODE(API_STATUS_NOK);
	else if (subtest->smw_status == SMW_STATUS_OEM_SRKH_NOT_FUSED)
		res = ERR_CODE(SKIPPED);

exit:
	if (args.data)
		free(args.data);

	if (msg.data)
		free(msg.data);

	return res;
}
