// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_keymgr.h>

#include "keymgr.h"
#include "util.h"
#include "util_key.h"
#include "util_tlv.h"

/**
 * kdf_tls12_read_args() - Read the TLS 1.2 function arguments
 * @kdf_args: SMW's TLS 1.2 arguments read
 * @oargs: Reference to the test definition json-c arguments array
 *
 * Note: the test definition array must define the arguments in the same
 * order as the SMW's structure definition.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
static int kdf_tls12_read_args(void **kdf_args, struct json_object *oargs)
{
	int res;
	struct tbuffer buf = { 0 };

	struct smw_kdf_tls12_args *tls_args = NULL;

	if (!kdf_args || !oargs) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	tls_args = calloc(1, sizeof(*tls_args));
	if (!tls_args)
		return INTERNAL_OUT_OF_MEMORY;

	res = UTIL_READ_JSON_ST_FIELD(tls_args, key_exchange_name, string,
				      oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = UTIL_READ_JSON_ST_FIELD(tls_args, encryption_name, string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = UTIL_READ_JSON_ST_FIELD(tls_args, prf_name, string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = UTIL_READ_JSON_ST_FIELD(tls_args, ext_master_key, boolean, oargs);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = util_read_json_type(&buf, "kdf_input", t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->kdf_input = buf.data;
	tls_args->kdf_input_length = buf.length;

	buf.data = NULL;
	buf.length = 0;

	res = util_read_json_type(&buf, "client_write_iv", t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->client_w_iv = buf.data;
	tls_args->client_w_iv_length = buf.length;

	buf.data = NULL;
	buf.length = 0;

	res = util_read_json_type(&buf, "server_write_iv", t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->server_w_iv = buf.data;
	tls_args->server_w_iv_length = buf.length;

	*kdf_args = tls_args;
	res = ERR_CODE(PASSED);

end:
	if (res != ERR_CODE(PASSED) && tls_args) {
		if (buf.data)
			free(buf.data);

		free(tls_args);
	}

	return res;
}

/**
 * kdf_tls12_prepare_result() - Prepare the TLS 1.2 results
 * @subtest: Subtest data
 * @key: Test keypair operation's result
 * @oargs: Reference to the json-c test output arguments definition
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_tls12_prepare_result(struct subtest_data *subtest,
				    struct keypair_ops *key,
				    struct json_object *okey_params)
{
	int res = ERR_CODE(PASSED);
	struct smw_keypair_buffer *buf;
	const char *key_name = NULL;

	/*
	 * If there is a "pub_key" argument, allocate a SMW's keypair
	 * and read the key definition.
	 */
	res = util_read_json_type(NULL, PUB_KEY_OBJ, t_buffer, okey_params);
	if (res != ERR_CODE(PASSED))
		return ERR_CODE(PASSED);

	buf = malloc(sizeof(*buf));
	if (!buf)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	res = util_key_desc_set_key(key, buf);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&key_name, OP_OUTPUT_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_key_read_descriptor(list_keys(subtest), key, key_name);

	return res;
}

/**
 * kdf_tls12_is_mac_key_expected() - Return if MAC key is expected
 * @encryption_name: Name of the encryption algorithm
 *
 * Return:
 * True     - MAC key is expected
 * False    - MAC key is not expected
 */
static bool kdf_tls12_is_mac_key_expected(const char *encryption_name)
{
	/* Server and client MAC keys are only generated for CBC cipher mode */
	if (encryption_name && (!strcmp(encryption_name, "3DES_EDE_CBC") ||
				!strcmp(encryption_name, "AES_128_CBC") ||
				!strcmp(encryption_name, "AES_256_CBC")))
		return true;

	return false;
}

static int store_key_identifier(struct llist *keys, const char *key,
				struct keypair_ops *key_test,
				struct json_object *params)
{
	int res;
	const char *key_name = NULL;

	if (!key || !key_test || !params) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_read_json_type(&key_name, key, t_string, params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_key_update_node(keys, key_name, key_test);

	return res;
}

/**
 * kdf_tls12_end_operation() - Finalize the TLS 1.2 operation
 * @subtest: Subtest data
 * @args: SMW's Key derivation arguments
 * @key_derived: Key derived result
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
int kdf_tls12_end_operation(struct subtest_data *subtest,
			    struct smw_derive_key_args *args,
			    struct keypair_ops *key_derived)
{
	int res;
	struct json_object *oargs = NULL;
	struct keypair_ops key_test = { 0 };
	struct smw_kdf_tls12_args *tls_args;
	struct llist *keys;

	if (!args || !subtest || !args->kdf_arguments) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	keys = list_keys(subtest);
	tls_args = args->kdf_arguments;

	/* Registers all generated keys in the test keys list */
	res = util_read_json_type(&oargs, OP_ARGS_OBJ, t_object,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!oargs)
		return ERR_CODE(MISSING_PARAMS);

	/* Even if it should not occur at this stage, check oargs */
	if (kdf_tls12_is_mac_key_expected(tls_args->encryption_name)) {
		key_test.desc.id = tls_args->client_w_mac_key_id;
		res = store_key_identifier(keys, CLIENT_W_MAC_KEY_NAME_OBJ,
					   &key_test, oargs);
		if (res != ERR_CODE(PASSED))
			return res;

		key_test.desc.id = tls_args->server_w_mac_key_id;
		res = store_key_identifier(keys, SERVER_W_MAC_KEY_NAME_OBJ,
					   &key_test, oargs);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	key_test.desc.id = tls_args->client_w_enc_key_id;
	res = store_key_identifier(keys, CLIENT_W_ENC_KEY_NAME_OBJ, &key_test,
				   oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	key_test.desc.id = tls_args->server_w_enc_key_id;
	res = store_key_identifier(keys, SERVER_W_ENC_KEY_NAME_OBJ, &key_test,
				   oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	key_test.desc.id = tls_args->master_sec_key_id;
	res = store_key_identifier(keys, MASTER_SEC_KEY_NAME_OBJ, &key_test,
				   oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	res = store_key_identifier(keys, OP_OUTPUT_OBJ, key_derived,
				   subtest->params);

	return res;
}

/**
 * kdf_tls12_free() - Free the TLS 1.2 operation arguments
 * @args: SMW's Key derivation arguments
 */
static void kdf_tls12_free(struct smw_derive_key_args *args)
{
	struct smw_kdf_tls12_args *tls_args;
	struct smw_key_descriptor *desc;

	if (args) {
		if (args->kdf_arguments) {
			tls_args = args->kdf_arguments;

			if (tls_args->kdf_input)
				free(tls_args->kdf_input);

			free(args->kdf_arguments);
			args->kdf_arguments = NULL;
		}

		if (args->key_descriptor_derived) {
			desc = args->key_descriptor_derived;
			if (desc->buffer)
				free(desc->buffer);
		}
	}
}

static const struct kdf_op {
	const char *name;
	int (*read_args)(void **kdf_args, struct json_object *oargs);
	int (*prepare_result)(struct subtest_data *subtest,
			      struct keypair_ops *key,
			      struct json_object *params);
	int (*end_operation)(struct subtest_data *subtest,
			     struct smw_derive_key_args *args,
			     struct keypair_ops *key_derived);
	void (*free)(struct smw_derive_key_args *args);
} kdf_ops[] = { {
			.name = "TLS12_KEY_EXCHANGE",
			.read_args = &kdf_tls12_read_args,
			.prepare_result = &kdf_tls12_prepare_result,
			.end_operation = &kdf_tls12_end_operation,
			.free = &kdf_tls12_free,
		},
		{ 0 } };

/**
 * get_kdf_op() - Find the Key Derivation name in the KDF operation
 * @kdf_name: Key Derivation name
 *
 * Return:
 * Pointer to the entry in the KDF operation list if found,
 * otherwise NULL
 */
static const struct kdf_op *get_kdf_op(const char *kdf_name)
{
	const struct kdf_op *entry = kdf_ops;

	if (kdf_name) {
		while (entry->name) {
			if (!strcmp(entry->name, kdf_name))
				return entry;
			entry++;
		}
	}

	return NULL;
}

/**
 * kdf_args_read() - Read Key Derivation Function name and arguments.
 * @args: Pointer to SMW's derive key args structure to update
 * @params: Pointer to json parameters
 *
 * Read the KDF name and its arguments from the test definition.
 * If no KDF name present, set the SMW's KDF name to NULL and return with
 * success.
 * If KDF name present, set the SMW's KDF name and try to get the KDF
 * arguments. If none, set the KDF argument to NULL and return success,
 * otherwise call the function to read and fill the KDF arguments.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
static int kdf_args_read(struct smw_derive_key_args *args,
			 struct json_object *params)
{
	int res;

	const struct kdf_op *kdf_op;
	struct json_object *oargs = NULL;

	/* Get the key derivation function if any */
	res = util_read_json_type(&args->kdf_name, OP_TYPE_OBJ, t_string,
				  params);

	if (res == ERR_CODE(VALUE_NOTFOUND)) {
		args->kdf_name = NULL;
		args->kdf_arguments = NULL;
		return ERR_CODE(PASSED);
	}

	if (res != ERR_CODE(PASSED))
		return res;

	kdf_op = get_kdf_op(args->kdf_name);

	if (!kdf_op) {
		args->kdf_arguments = NULL;
	} else if (kdf_op->read_args) {
		res = util_read_json_type(&oargs, OP_ARGS_OBJ, t_object,
					  params);
		if (res == ERR_CODE(PASSED) && oargs)
			res = kdf_op->read_args(&args->kdf_arguments, oargs);
	}

	return res;
}

/**
 * setup_derive_opt_params() - Setup key derive optional parameters.
 * @subtest: Subtest data
 * @args: Pointer to SMW's derive key arguments
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
static int setup_derive_opt_params(struct subtest_data *subtest,
				   struct smw_derive_key_args *args)
{
	int res;
	struct json_object *okey_params = NULL;

	unsigned char **attrs;
	unsigned int *attrs_len;

	if (!subtest || !args) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_key_get_key_params(subtest, OP_INPUT_OBJ, &okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	attrs = (unsigned char **)&args->key_attributes_list;
	attrs_len = &args->key_attributes_list_length;

	/* Get the key policy */
	res = util_tlv_read_key_policy(attrs, attrs_len, okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs(attrs, attrs_len, okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read (if any) the key derivation function name and arguments */
	res = kdf_args_read(args, subtest->params);

	return res;
}

/**
 * setup_derive_output() - Setup the key derivation output arguments.
 * @subtest: Subtest data
 * @args: Pointer to SMW's derive key arguments
 * @key: Test keypair operation's result
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int setup_derive_output(struct subtest_data *subtest,
			       struct smw_derive_key_args *args,
			       struct keypair_ops *key)
{
	int res = ERR_CODE(PASSED);

	const struct kdf_op *kdf_op;
	struct json_object *okey_params = NULL;

	kdf_op = get_kdf_op(args->kdf_name);

	if (kdf_op && kdf_op->prepare_result) {
		res = util_key_get_key_params(subtest, OP_OUTPUT_OBJ,
					      &okey_params);
		if (res != ERR_CODE(PASSED))
			return res;

		if (res == ERR_CODE(PASSED) && okey_params)
			res = kdf_op->prepare_result(subtest, key, okey_params);
	}

	return res;
}

/**
 * setup_derive_base() - Setup the key derivation base argument.
 * @subtest: Subtest data.
 * @key_base: Test keypair operation's base.
 * @base_buffer: Pointer to base keypair buffer structure.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -FAILED                  - Error in definition file
 * -API_STATUS_NOK          - SMW API Call return error
 */
static int setup_derive_base(struct subtest_data *subtest,
			     struct keypair_ops *key_base,
			     struct smw_keypair_buffer *base_buffer)
{
	int res = ERR_CODE(FAILED);
	const char *key_name = NULL;

	/* Initialize key descriptor */
	res = util_key_desc_init(key_base, base_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&key_name, OP_INPUT_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(list_keys(subtest), key_base, key_name);

	return res;
}

/**
 * end_derive_operation() - End key derivation operations.
 * @subtest: Subtest data
 * @args: Pointer to SMW's derive key arguments
 * @key_derived: Key derived result
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int end_derive_operation(struct subtest_data *subtest,
				struct smw_derive_key_args *args,
				struct keypair_ops *key_derived)
{
	int res = ERR_CODE(FAILED);

	const struct kdf_op *kdf_op;

	kdf_op = get_kdf_op(args->kdf_name);

	if (kdf_op && kdf_op->end_operation)
		res = kdf_op->end_operation(subtest, args, key_derived);

	return res;
}

/**
 * kdf_args_free() - Free the Key Derivation Function arguments
 * @args: Pointer to SMW's derive key arguments structure to free
 */
static void kdf_args_free(struct smw_derive_key_args *args)
{
	const struct kdf_op *kdf_op;

	kdf_op = get_kdf_op(args->kdf_name);
	if (kdf_op && kdf_op->free)
		kdf_op->free(args);
}

static int derive_bad_params(struct json_object *params,
			     struct smw_derive_key_args **args)
{
	int ret;
	enum arguments_test_err_case error;

	if (!params || !args)
		return ERR_CODE(BAD_ARGS);

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
		(*args)->key_descriptor_base = NULL;
		break;

	case KEY_DESC_OUT_NULL:
		(*args)->key_descriptor_derived = NULL;
		break;

	case TLS12_KDF_ARGS_NULL:
		(*args)->kdf_arguments = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int derive_key(struct subtest_data *subtest)
{
	int res = ERR_CODE(FAILED);
	struct keypair_ops key_base = { 0 };
	struct keypair_ops key_derived = { 0 };
	struct smw_keypair_buffer base_buffer = { 0 };
	struct smw_derive_key_args args = { 0 };
	struct smw_derive_key_args *smw_args = &args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	if (subtest->subsystem && !strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	args.key_descriptor_base = &key_base.desc;
	args.key_descriptor_derived = &key_derived.desc;

	/* Setup key descriptor or the key base */
	res = setup_derive_base(subtest, &key_base, &base_buffer);
	if (res != ERR_CODE(PASSED) && !is_api_test(subtest))
		goto exit;

	/* Setup optional parameters */
	res = setup_derive_opt_params(subtest, &args);
	if (res != ERR_CODE(PASSED) && !is_api_test(subtest))
		goto exit;

	/*
	 * Initialize key descriptor of the key derived
	 * No key buffer and type of key unknown
	 */
	res = util_key_desc_init(&key_derived, NULL);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Setup the output arguments */
	res = setup_derive_output(subtest, &args, &key_derived);
	if (res != ERR_CODE(PASSED) && !is_api_test(subtest))
		goto exit;

	res = derive_bad_params(subtest->params, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	subtest->smw_status = smw_derive_key(smw_args);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);
	else
		res = end_derive_operation(subtest, &args, &key_derived);

exit:
	util_key_free_key(&key_base);

	/*
	 * Don't free key data if it's present in key linked list
	 * (ephemeral keys)
	 */
	if (util_key_is_id_set(&key_derived))
		util_key_free_key(&key_derived);

	kdf_args_free(&args);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}
