// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_keymgr.h>
#include <smw_crypto.h>

#include "util.h"
#include "util_attr.h"
#include "util_sign.h"
#include "util_context.h"

#include "key.h"
#include "sign_verify.h"

#define ONESHOT 0
#define INIT	1
#define UPDATE	2
#define FINAL	3

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
	if (key_desc->type_name == SMW_KEY_TYPE_NAME_NONE &&
	    smw_get_key_type_name(key_desc) != SMW_STATUS_OK)
		return 0;

	if (!key_desc->security_size &&
	    smw_get_security_size(key_desc) != SMW_STATUS_OK)
		return 0;

	if (key_desc->type_name == SMW_KEY_TYPE_NAME_SECP_R1 ||
	    key_desc->type_name == SMW_KEY_TYPE_NAME_BRAINPOOL_R1 ||
	    key_desc->type_name == SMW_KEY_TYPE_NAME_BRAINPOOL_T1 ||
	    key_desc->type_name == SMW_KEY_TYPE_NAME_ED25519)
		return BITS_TO_BYTES_SIZE(key_desc->security_size) * 2;

	if (key_desc->type_name == SMW_KEY_TYPE_NAME_ED448)
		return (BITS_TO_BYTES_SIZE(key_desc->security_size) * 2 + 2);

	if (key_desc->type_name == SMW_KEY_TYPE_NAME_RSA)
		return BITS_TO_BYTES_SIZE(key_desc->security_size);

	if (key_desc->type_name == SMW_KEY_TYPE_NAME_TLS_MASTER)
		return TLS12_MAC_FINISH_DEFAULT_LEN;

	return 0;
}

/**
 * set_sign_verify_init_bad_args() - Set sign/verify init bad parameters.
 * @subtest: Subtest data.
 * @args: SMW Sign/Verify parameters.
 * @step: Operation step define value
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
static int set_sign_verify_bad_args(struct subtest_data *subtest, void **args,
				    unsigned int step)
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

	case KEY_DESC_NULL:
		if (step == ONESHOT)
			(*(struct smw_sign_verify_args **)args)->key_descriptor =
				NULL;
		else if (step == INIT)
			(*(struct smw_sign_verify_init_args **)args)
				->key_descriptor = NULL;

		break;

	case CTX_NULL:
		if (step == INIT)
			(*(struct smw_sign_verify_init_args **)args)->context =
				NULL;
		else if (step == UPDATE)
			(*(struct smw_sign_verify_update_args **)args)->context =
				NULL;
		else if (step == FINAL)
			(*(struct smw_sign_verify_final_args **)args)->context =
				NULL;

		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

static int read_public_key_descriptor(struct llist *keys,
				      struct keypair_ops *key_test,
				      const char *key_name)
{
	int ret = ERR_CODE(PASSED);
	struct key_data *data = NULL;
	const char *type_string = NULL;
	const char *format_string = NULL;
	struct smw_key_descriptor *desc = &key_test->desc;

	if (!desc || !key_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	/*
	 * For a given key, if the key ID is 0 and a public key buffer is present
	 * in the key's linked list node, copy the buffer from the node and
	 * retrieve the key type, size, and format from the test definition file.
	 * This scenario typically occurs when a public key buffer is exported
	 * using the smw_export_key() API, and is later used for signature
	 * verification.
	 */
	if (!data->identifier && data->pub_key.data && data->pub_key.length) {
		*key_public_length(key_test) = data->pub_key.length;
		*key_public_data(key_test) = malloc(data->pub_key.length);
		if (!*key_public_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(*key_public_data(key_test), data->pub_key.data,
		       data->pub_key.length);

		/* Read 'type' parameter if defined */
		ret = util_read_json_type(&type_string, TYPE_OBJ, t_string,
					  data->okey_params);
		if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
			return ret;

		if (ret == ERR_CODE(PASSED))
			desc->type_name = key_get_type_name(type_string);

		/* Read 'security_size' parameter if defined */
		ret = util_read_json_type(&desc->security_size, SEC_SIZE_OBJ,
					  t_int, data->okey_params);
		if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
			return ret;

		/* Read 'format' parameter if defined */
		ret = util_read_json_type(&format_string, FORMAT_OBJ, t_string,
					  data->okey_params);
		if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
			return ret;

		desc->buffer->format_name = key_get_format_name(format_string);

		ret = ERR_CODE(PASSED);

	} else {
		ret = key_read_descriptor(keys, key_test, key_name);
	}

	return ret;
}

static int get_signature_key(struct subtest_data *subtest,
			     struct keypair_ops *key_test,
			     struct smw_keypair_buffer *key_buffer,
			     int operation)
{
	int res = ERR_CODE(PASSED);

	const char *key_name = NULL;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Initialize key descriptor */
	res = key_desc_init(key_test, key_buffer);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (operation == SIGN_OPERATION)
		/* Read the json-c key description */
		res = key_read_descriptor(list_keys(subtest), key_test,
					  key_name);
	else
		res = read_public_key_descriptor(list_keys(subtest), key_test,
						 key_name);

	if (res != ERR_CODE(PASSED))
		goto end;

	if (key_is_id_set(key_test)) {
		key_free_key(key_test);
	} else if (!key_is_type_set(key_test) ||
		   !key_is_security_set(key_test) ||
		   (operation == SIGN_OPERATION &&
		    !key_is_private_key_defined(key_test)) ||
		   (operation == VERIFY_OPERATION &&
		    !key_is_public_key_defined(key_test))) {
		DBG_PRINT_MISS_PARAM("Key description");
		res = ERR_CODE(MISSING_PARAMS);
	}

end:
	return res;
}

static int set_signature_to_generate(struct subtest_data *subtest,
				     struct smw_key_descriptor *key_desc,
				     unsigned char **signature,
				     unsigned int *length)
{
	int res = ERR_CODE(PASSED);

	int sign_id = INT_MAX;
	unsigned char *list_sign = NULL;
	unsigned int list_sign_length = 0;

	*length = 0;
	*signature = NULL;

	/* Get 'sign_id' parameter */
	res = util_read_json_type(&sign_id, SIGN_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (sign_id != INT_MAX) {
		res = util_sign_find_node(list_signatures(subtest), sign_id,
					  &list_sign, &list_sign_length);

		/* 'sign_id' must not be in the signatures list */
		if (res == ERR_CODE(PASSED)) {
			DBG_PRINT_BAD_PARAM(SIGN_ID_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto end;
		}
	}

	*length = get_signature_len(key_desc);
	if (!*length) {
		res = ERR_CODE(PASSED);
		goto end;
	}

	*signature = malloc(*length);
	if (!*signature) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	res = ERR_CODE(PASSED);

end:
	return res;
}

static int get_signature_to_verify(struct subtest_data *subtest,
				   unsigned char **signature,
				   unsigned int *length)
{
	int res = ERR_CODE(PASSED);

	int sign_id = INT_MAX;

	/* Get 'sign_id' parameter */
	res = util_read_json_type(&sign_id, SIGN_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (sign_id == INT_MAX) {
		res = ERR_CODE(PASSED);
		goto end;
	}

	res = util_sign_find_node(list_signatures(subtest), sign_id, signature,
				  length);

	/* 'sign_id' must be in the signatures list */
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT_BAD_PARAM(SIGN_ID_OBJ);
		res = ERR_CODE(BAD_PARAM_TYPE);
	}

end:
	return res;
}

static int end_signature_generation(struct subtest_data *subtest,
				    unsigned char **sign, unsigned int length,
				    unsigned char *exp_sign,
				    unsigned int exp_length)
{
	int res = ERR_CODE(PASSED);

	int sign_id = INT_MAX;

	if (!*sign) {
		if (length != exp_length) {
			DBG_PRINT("Bad Sign length got %d expected %d", length,
				  exp_length);
			res = ERR_CODE(SUBSYSTEM);
		}

		goto end;
	}

	if (exp_sign) {
		res = util_compare_buffers(*sign, length, exp_sign, exp_length);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	/* Get 'sign_id' parameter */
	res = util_read_json_type(&sign_id, SIGN_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (sign_id != INT_MAX) {
		/* Store signature */
		res = util_sign_add_node(list_signatures(subtest), sign_id,
					 *sign, length);
	} else {
		res = ERR_CODE(PASSED);
		if (*sign) {
			free(*sign);
			*sign = NULL;
		}
	}

end:
	return res;
}

int sign_verify(struct subtest_data *subtest, int operation)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	unsigned int message_length = 0;
	unsigned int context_length = 0;
	unsigned int exp_sign_length = 0;
	unsigned char *message = NULL;
	unsigned char *context = NULL;
	unsigned char *exp_sign = NULL;
	struct smw_sign_verify_args args = { 0 };
	struct smw_sign_verify_args *smw_sign_verify_args = &args;
	struct smw_eddsa_params eddsa_params = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (operation != SIGN_OPERATION && operation != VERIFY_OPERATION)
		return ERR_CODE(UNDEFINED_CMD);

	args.version = subtest->version;
	args.subsystem_name = subtest->subsystem;

	res = get_signature_key(subtest, &key_test, &key_buffer, operation);
	if (res != ERR_CODE(PASSED))
		goto exit;

	args.key_descriptor = &key_test.desc;

	/* Signature attributes are not mandatory in case of error test */
	res = util_attr_read_attributes(subtest->params, SIGN_ATTR_OBJ,
					&algorithm_callback, &args.sign_algo);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Read message buffer if any */
	res = util_read_hex_buffer(&message, &message_length, subtest->params,
				   MESS_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	args.message = message;
	args.message_length = message_length;

	/* Read context signature parameters if any */
	res = util_read_hex_buffer(&context, &context_length, subtest->params,
				   CTX_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	if (res == ERR_CODE(PASSED)) {
		if (key_test.desc.type_name == SMW_KEY_TYPE_NAME_ED25519 ||
		    key_test.desc.type_name == SMW_KEY_TYPE_NAME_ED448) {
			eddsa_params.context = context;
			eddsa_params.context_length = context_length;

			args.eddsa_params = &eddsa_params;
		}
	}

	/* Read expected signature buffer if any */
	res = util_read_hex_buffer(&exp_sign, &exp_sign_length, subtest->params,
				   SIGN_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	if (operation == SIGN_OPERATION) {
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
			args.signature = exp_sign;
			args.signature_length = exp_sign_length;
		} else {
			res = set_signature_to_generate(subtest,
							args.key_descriptor,
							&args.signature,
							&args.signature_length);
		}
	} else {
		args.signature = exp_sign;
		args.signature_length = exp_sign_length;

		res = get_signature_to_verify(subtest, &args.signature,
					      &args.signature_length);
	}

	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_sign_verify_bad_args(subtest, (void **)&smw_sign_verify_args,
				       ONESHOT);
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

	if (operation == SIGN_OPERATION)
		res = end_signature_generation(subtest, &args.signature,
					       args.signature_length, exp_sign,
					       exp_sign_length);

exit:
	key_free_key(&key_test);

	if (message)
		free(message);

	if (context)
		free(context);

	if (operation == SIGN_OPERATION) {
		if (res != ERR_CODE(PASSED) && args.signature != exp_sign)
			free(args.signature);
	}

	if (exp_sign)
		free(exp_sign);

	return res;
}

int sign_verify_init(struct subtest_data *subtest, int operation)
{
	int res = ERR_CODE(BAD_ARGS);

	struct keypair_ops key_test = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	unsigned int ctx_id = UINT_MAX;
	unsigned char *message = NULL;
	unsigned int message_length = 0;
	unsigned char *context = NULL;
	unsigned int context_length = 0;

	struct smw_sign_verify_init_args args = { 0 };
	struct smw_sign_verify_init_args *smw_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;
	struct smw_eddsa_params eddsa_params = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (operation != SIGN_OPERATION && operation != VERIFY_OPERATION)
		return ERR_CODE(UNDEFINED_CMD);

	args.version = subtest->version;
	args.subsystem_name = subtest->subsystem;

	res = get_signature_key(subtest, &key_test, &key_buffer, operation);
	if (res != ERR_CODE(PASSED))
		goto end;

	args.key_descriptor = &key_test.desc;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Signature attributes are not mandatory in case of error test */
	res = util_attr_read_attributes(subtest->params, SIGN_ATTR_OBJ,
					&algorithm_callback, &args.sign_algo);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	/* Read context signature parameters if any */
	res = util_read_hex_buffer(&context, &context_length, subtest->params,
				   CTX_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto end;

	if (res == ERR_CODE(PASSED)) {
		if (key_test.desc.type_name == SMW_KEY_TYPE_NAME_ED25519 ||
		    key_test.desc.type_name == SMW_KEY_TYPE_NAME_ED448) {
			eddsa_params.context = context;
			eddsa_params.context_length = context_length;

			args.eddsa_params = &eddsa_params;
		}
	}

	/* Read message buffer if any */
	res = util_read_hex_buffer(&message, &message_length, subtest->params,
				   MESS_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto end;

	args.message = message;
	args.message_length = message_length;

	/* Specific test cases */
	res = set_sign_verify_bad_args(subtest, (void **)&smw_args, INIT);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (operation == SIGN_OPERATION)
		subtest->smw_status = smw_sign_init(smw_args);
	else /* operation == VERIFY_OPERATION */
		subtest->smw_status = smw_verify_init(smw_args);

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);

		if (!args.context) {
			res = util_context_update_node(list_op_ctxs(subtest),
						       ctx_id, args.context);
			if (res != ERR_CODE(PASSED))
				DBG_PRINT("Failed to update context node data");
		}
	}

end:
	key_free_key(&key_test);

	if (message)
		free(message);

	if (context)
		free(context);

	return res;
}

int sign_verify_update(struct subtest_data *subtest, int operation)
{
	int res = ERR_CODE(BAD_ARGS);

	unsigned int ctx_id = UINT_MAX;
	unsigned char *message = NULL;
	unsigned int message_length = 0;

	struct smw_sign_verify_update_args args = { 0 };
	struct smw_sign_verify_update_args *smw_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read input buffer if any */
	res = util_read_hex_buffer(&message, &message_length, subtest->params,
				   MESS_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto end;

	args.message = message;
	args.message_length = message_length;

	/* Specific test cases */
	res = set_sign_verify_bad_args(subtest, (void **)&smw_args, UPDATE);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (operation == SIGN_OPERATION)
		subtest->smw_status = smw_sign_update(smw_args);
	else /* operation == VERIFY_OPERATION */
		subtest->smw_status = smw_verify_update(smw_args);

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);

		if (!args.context) {
			res = util_context_update_node(list_op_ctxs(subtest),
						       ctx_id, args.context);
			if (res != ERR_CODE(PASSED))
				DBG_PRINT("Failed to update context node data");
		}
	}

end:
	if (message)
		free(message);

	return res;
}

int sign_verify_final(struct subtest_data *subtest, int operation)
{
	int res = ERR_CODE(BAD_ARGS);

	unsigned int ctx_id = UINT_MAX;
	unsigned char *message = NULL;
	unsigned int message_length = 0;
	unsigned char *exp_sign = NULL;
	unsigned int exp_sign_length = 0;

	struct smw_sign_verify_final_args args = { 0 };
	struct smw_sign_verify_final_args *smw_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read input buffer if any */
	res = util_read_hex_buffer(&message, &message_length, subtest->params,
				   MESS_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto end;

	args.message = message;
	args.message_length = message_length;

	/* Read expected signature buffer if any */
	res = util_read_hex_buffer(&exp_sign, &exp_sign_length, subtest->params,
				   SIGN_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto end;

	if (operation == SIGN_OPERATION) {
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
			args.signature = exp_sign;
			args.signature_length = exp_sign_length;
		} else {
			subtest->smw_status = smw_sign_final(smw_args);
			if (subtest->smw_status != SMW_STATUS_OK) {
				res = ERR_CODE(API_STATUS_NOK);
				goto end;
			}

			if (args.signature_length)
				args.signature = malloc(args.signature_length);

			if (!args.signature) {
				DBG_PRINT_ALLOC_FAILURE();
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto end;
			}
		}
	} else {
		args.signature = exp_sign;
		args.signature_length = exp_sign_length;

		res = get_signature_to_verify(subtest, &args.signature,
					      &args.signature_length);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	/* Specific test cases */
	res = set_sign_verify_bad_args(subtest, (void **)&smw_args, FINAL);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (operation == SIGN_OPERATION)
		subtest->smw_status = smw_sign_final(smw_args);
	else /* operation == VERIFY_OPERATION */
		subtest->smw_status = smw_verify_final(smw_args);

	if (operation == SIGN_OPERATION && subtest->smw_status == SMW_STATUS_OK)
		res = end_signature_generation(subtest, &args.signature,
					       args.signature_length, exp_sign,
					       exp_sign_length);

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);

		if (!args.context) {
			res = util_context_update_node(list_op_ctxs(subtest),
						       ctx_id, args.context);
			if (res != ERR_CODE(PASSED))
				DBG_PRINT("Failed to update context node data");
		}
	}

end:
	if (message)
		free(message);

	if (operation == SIGN_OPERATION) {
		if (res != ERR_CODE(PASSED) && args.signature != exp_sign)
			free(args.signature);
	}

	if (exp_sign)
		free(exp_sign);

	return res;
}
