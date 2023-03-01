// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_keymgr.h>
#include <smw_crypto.h>

#include "util.h"
#include "util_sign.h"
#include "util_tlv.h"

#include "key.h"
#include "sign_verify.h"

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
	if (!key_desc->type_name &&
	    smw_get_key_type_name(key_desc) != SMW_STATUS_OK)
		return 0;

	if (!key_desc->security_size &&
	    smw_get_security_size(key_desc) != SMW_STATUS_OK)
		return 0;

	if (!strcmp(key_desc->type_name, BR1_KEY) ||
	    !strcmp(key_desc->type_name, BT1_KEY) ||
	    !strcmp(key_desc->type_name, NIST_KEY))
		return BITS_TO_BYTES_SIZE(key_desc->security_size) * 2;

	if (!strcmp(key_desc->type_name, RSA_KEY))
		return BITS_TO_BYTES_SIZE(key_desc->security_size);

	if (!strcmp(key_desc->type_name, TLS_MASTER_KEY))
		return TLS12_MAC_FINISH_DEFAULT_LEN;

	return 0;
}

/**
 * set_sign_verify_bad_args() - Set sign/verify bad parameters.
 * @subtest: Subtest data.
 * @args: SMW Sign/Verify parameters.
 * @signature: expected signature buffer argument parameter.
 * @signature_length: expected signature length argument parameter.
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
static int set_sign_verify_bad_args(struct subtest_data *subtest,
				    struct smw_sign_verify_args **args,
				    unsigned char *signature,
				    unsigned int signature_length)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!subtest || !args)
		return ERR_CODE(BAD_ARGS);

	/*
	 * In case of API test, the parameter "signature"
	 * can explicitly define the signature buffer.
	 * Otherwise it is ignored.
	 */
	if (is_api_test(subtest)) {
		/*
		 * In case of Sign operation, the signature buffer
		 * may have been already allocated.
		 */
		(*args)->signature = signature;
		(*args)->signature_length = signature_length;
	}

	ret = util_read_test_error(&error, subtest->params);
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
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int sign_verify(struct subtest_data *subtest, int operation)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test;
	struct smw_keypair_buffer key_buffer;
	const char *key_name = NULL;
	int sign_id = INT_MAX;
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

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (operation != SIGN_OPERATION && operation != VERIFY_OPERATION)
		return ERR_CODE(UNDEFINED_CMD);

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	args.key_descriptor = &key_test.desc;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Initialize key descriptor */
	res = key_desc_init(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_is_id_set(&key_test))
		key_free_key(&key_test);

	if (!key_is_id_set(&key_test) &&
	    (!key_is_type_set(&key_test) || !key_is_security_set(&key_test) ||
	     (operation == SIGN_OPERATION &&
	      !key_is_private_key_defined(&key_test)) ||
	     (operation == VERIFY_OPERATION &&
	      !key_is_public_key_defined(&key_test)))) {
		DBG_PRINT_MISS_PARAM("Key description");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Get 'algo' optional parameter */
	res = util_read_json_type(&args.algo_name, ALGO_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Read message buffer if any */
	res = util_read_hex_buffer(&message, &message_length, subtest->params,
				   MESS_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	args.message = message;
	args.message_length = message_length;

	/* Get 'sign_id' parameter */
	res = util_read_json_type(&sign_id, SIGN_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (sign_id != INT_MAX) {
		res = util_sign_find_node(list_signatures(subtest), sign_id,
					  &list_sign, &list_sign_length);

		if (operation == SIGN_OPERATION) {
			/* 'sign_id' must not be in the signatures list */
			if (res == ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(SIGN_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}
			new_sign_length = get_signature_len(&key_test.desc);

			if (new_sign_length) {
				new_sign = malloc(new_sign_length);
				if (!new_sign) {
					DBG_PRINT_ALLOC_FAILURE();
					res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
					goto exit;
				}
			}

			args.signature = new_sign;
			args.signature_length = new_sign_length;
		} else /* operation == VERIFY_OPERATION */ {
			/* 'sign_id' must be in the signatures list */
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(SIGN_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}

			args.signature = list_sign;
			args.signature_length = list_sign_length;
		}
	}

	/* Read expected signature buffer if any */
	res = util_read_hex_buffer(&exp_sign, &exp_sign_length, subtest->params,
				   SIGN_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	/* Specific test cases */
	res = set_sign_verify_bad_args(subtest, &smw_sign_verify_args, exp_sign,
				       exp_sign_length);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args.attributes_list,
				  &args.attributes_list_length,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call operation function and compare result with expected one */
	if (operation == SIGN_OPERATION)
		subtest->smw_status = smw_sign(smw_sign_verify_args);
	else /* operation == VERIFY_OPERATION */
		subtest->smw_status = smw_verify(smw_sign_verify_args);

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (operation == SIGN_OPERATION) {
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
		res = util_sign_add_node(list_signatures(subtest), sign_id,
					 args.signature, args.signature_length);
		if (res)
			args.signature = NULL;
	}

exit:
	key_free_key(&key_test);

	if (message)
		free(message);

	if (new_sign && new_sign != args.signature)
		free(new_sign);

	if (exp_sign)
		if (operation != SIGN_OPERATION || exp_sign != args.signature)
			free(exp_sign);

	return res;
}
