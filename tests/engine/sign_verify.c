// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "util_sign.h"
#include "types.h"
#include "crypto.h"
#include "json_types.h"
#include "keymgr.h"
#include "smw_keymgr.h"
#include "smw_crypto.h"
#include "smw_status.h"
#include "sign_verify.h"
#include "util_tlv.h"

/* Signatures linked list */
static struct signature_list *signatures;

/**
 * get_signature_len() - Return signature byte length given security size.
 * @key_desc: Pointer to key descriptor
 *
 * Return:
 * The signature length in bytes.
 * 0 if key type not supported.
 */
static unsigned int get_signature_len(struct smw_key_descriptor *key_desc)
{
	int status = smw_get_key_type_name(key_desc);

	if (status != SMW_STATUS_OK)
		return 0;

	if (!strcmp(key_desc->type_name, BR1_KEY) ||
	    !strcmp(key_desc->type_name, BT1_KEY) ||
	    !strcmp(key_desc->type_name, NIST_KEY))
		return BITS_TO_BYTES_SIZE(key_desc->security_size) * 2;

	if (!strcmp(key_desc->type_name, RSA_KEY))
		return BITS_TO_BYTES_SIZE(key_desc->security_size);

	return 0;
}

/**
 * set_sign_verify_bad_args() - Set sign/verify bad parameters.
 * @operation: SIGN_OPERATION or VERIFY_OPERATION.
 * @params: json-c object
 * @args: SMW Sign/Verify parameters.
 * @signature: expected signature buffer argument parameter.
 * @signature_length: expected signature length argument parameter.
 * @is_api_test: Test concerns the API validation.
 *
 * These configurations represent specific error cases
 * using SMW API for Sign/Verify.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_sign_verify_bad_args(int operation, json_object *params,
				    struct smw_sign_verify_args **args,
				    unsigned char *signature,
				    unsigned int signature_length,
				    int is_api_test)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error;

	if (!params || !args)
		return ERR_CODE(BAD_ARGS);

	/*
	 * In case of API test, the parameter "signature"
	 * can explicitly define the signature buffer.
	 * Otherwise it is ignored.
	 */
	if (is_api_test) {
		/*
		 * In case of Sign operation, the signature buffer
		 * may have been already allocated.
		 */
		(*args)->signature = signature;
		(*args)->signature_length = signature_length;
	}

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case KEY_DESC_NULL:
		(*args)->key_descriptor = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int sign_verify(int operation, json_object *params,
		struct common_parameters *common_params, char *algo_name,
		struct key_identifier_list *key_identifiers, int *ret_status)
{
	int res = ERR_CODE(PASSED);
	int status = SMW_STATUS_OPERATION_FAILURE;
	struct keypair_ops key_test;
	struct smw_keypair_buffer key_buffer;
	int key_id = INT_MAX;
	unsigned int message_length = 0;
	unsigned int list_sign_length = 0;
	unsigned int new_sign_length = 0;
	unsigned int exp_sign_length = 0;
	unsigned char *message = NULL;
	unsigned char *list_sign = NULL;
	unsigned char *new_sign = NULL;
	unsigned char *exp_sign = NULL;
	struct smw_sign_verify_args args = { 0 };
	struct smw_sign_verify_args *smw_sign_verify_args = &args;
	json_object *sign_id_obj = NULL;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	if (operation != SIGN_OPERATION && operation != VERIFY_OPERATION)
		return ERR_CODE(UNDEFINED_CMD);

	args.version = common_params->version;

	if (!strcmp(common_params->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = common_params->subsystem;

	args.key_descriptor = &key_test.desc;

	/* Initialize key descriptor */
	res = util_key_desc_init(&key_test, &key_buffer, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, params);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_id != INT_MAX) {
		util_key_free_key(&key_test);
		key_test.desc.buffer = NULL;
		key_test.keys = NULL;
		util_key_set_ops(&key_test, NULL);

		/* Fill key descriptor field saved */
		res = util_key_find_key_node(key_identifiers, key_id,
					     &key_test);
		if (res != ERR_CODE(PASSED))
			goto exit;

		/*
		 * If Security size not set,
		 * get it from the SMW key identifier
		 */
		if (!util_key_is_security_set(&key_test)) {
			status = smw_get_security_size(&key_test.desc);
			if (status != SMW_STATUS_OK) {
				res = ERR_CODE(BAD_RESULT);
				goto exit;
			}
		}
	} else if (!util_key_is_type_set(&key_test) ||
		   !util_key_is_security_set(&key_test) ||
		   ((operation == SIGN_OPERATION) &&
		    !util_key_is_private_key_defined(&key_test)) ||
		   ((operation == VERIFY_OPERATION) &&
		    !util_key_is_public_key_defined(&key_test))) {
		DBG_PRINT_MISS_PARAM(__func__, "Key description");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	args.algo_name = algo_name;

	/* Read message buffer if any */
	res = util_read_hex_buffer(&message, &message_length, params, MESS_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	args.message = message;
	args.message_length = message_length;

	/* Get 'sign_id' parameter */
	if (json_object_object_get_ex(params, SIGN_ID_OBJ, &sign_id_obj)) {
		res = util_sign_find_node(signatures,
					  json_object_get_int(sign_id_obj),
					  &list_sign, &list_sign_length);

		if (operation == SIGN_OPERATION) {
			/* 'sign_id' must not be in the signatures list */
			if (res == ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(__func__, SIGN_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}
			new_sign_length = get_signature_len(&key_test.desc);

			if (new_sign_length) {
				new_sign = malloc(new_sign_length);
				if (!new_sign) {
					DBG_PRINT_ALLOC_FAILURE(__func__,
								__LINE__);
					res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
					goto exit;
				}
			}

			args.signature = new_sign;
			args.signature_length = new_sign_length;
		} else /* operation == VERIFY_OPERATION */ {
			/* 'sign_id' must be in the signatures list */
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(__func__, SIGN_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}

			args.signature = list_sign;
			args.signature_length = list_sign_length;
		}
	}

	/* Read expected signature buffer if any */
	res = util_read_hex_buffer(&exp_sign, &exp_sign_length, params,
				   SIGN_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	/* Specific test cases */
	res = set_sign_verify_bad_args(operation, params, &smw_sign_verify_args,
				       exp_sign, exp_sign_length,
				       common_params->is_api_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args.attributes_list,
				  &args.attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call operation function and compare result with expected one */
	if (operation == SIGN_OPERATION)
		*ret_status = smw_sign(smw_sign_verify_args);
	else /* operation == VERIFY_OPERATION */
		*ret_status = smw_verify(smw_sign_verify_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	if (*ret_status == SMW_STATUS_OK && operation == SIGN_OPERATION) {
		if (!args.signature) {
			if (args.signature_length != exp_sign_length) {
				DBG_PRINT("Bad Sign length got %d expected %d",
					  args.signature_length,
					  exp_sign_length);
				res = ERR_CODE(SUBSYSTEM);
			}

			goto exit;
		}

		/* Store signature */
		res = util_sign_add_node(&signatures,
					 json_object_get_int(sign_id_obj),
					 args.signature, args.signature_length);
		if (res)
			args.signature = NULL;
	}

exit:
	util_key_free_key(&key_test);

	if (message)
		free(message);

	if (new_sign && new_sign != args.signature)
		free(new_sign);

	if (exp_sign)
		if (operation != SIGN_OPERATION || exp_sign != args.signature)
			free(exp_sign);

	return res;
}

void sign_clear_signatures_list(void)
{
	util_sign_clear_list(signatures);
}
