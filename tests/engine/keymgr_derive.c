// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "keymgr.h"
#include "util.h"
#include "util_tlv.h"

#include "smw_status.h"

/*
 * This identifier is used for test error tests.
 * It represents the following key:
 *  - Generated/Imported by subsystem ID 0
 *  - Type is ECDSA NIST
 *  - Parity is private
 *  - Security size is 256
 *  - Subsystem Key ID is 1
 */
#define FAKE_KEY_ID_NIST_256_0_ID INT64_C(0x0010010000000001)

#define READ_KDF_ARGS(st, f, type, jobj)                                       \
	({                                                                     \
		int _ret;                                                      \
		do {                                                           \
			unsigned char *_elm = (unsigned char *)(st);           \
			_elm += offsetof(struct smw_kdf_tls12_args, f);        \
			_ret = util_read_json_type(_elm, #f, t_##type, jobj);  \
		} while (0);                                                   \
		_ret;                                                          \
	})

/**
 * kdf_args_tls12_read() - Read the TLS 1.2 function arguments
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
static int kdf_tls12_args_read(void **kdf_args, json_object *oargs)
{
	int res;
	struct tbuffer buf = { 0 };

	struct smw_kdf_tls12_args *tls_args = NULL;

	if (!kdf_args || !oargs) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	tls_args = calloc(1, sizeof(*tls_args));
	if (!tls_args)
		return INTERNAL_OUT_OF_MEMORY;

	res = READ_KDF_ARGS(tls_args, key_exchange_name, string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = READ_KDF_ARGS(tls_args, encryption_name, string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = READ_KDF_ARGS(tls_args, prf_name, string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = READ_KDF_ARGS(tls_args, ext_master_key, boolean, oargs);
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
static int kdf_tls12_prepare_result(struct keypair_ops *key, json_object *oargs)
{
	int res = ERR_CODE(PASSED);
	struct smw_keypair_buffer *buf;

	/*
	 * If there is a "pub_key" argument, allocate a SMW's keypair
	 * and read the key definition.
	 */
	if (util_read_json_type(NULL, PUB_KEY_OBJ, t_buffer, oargs) ==
	    ERR_CODE(PASSED)) {
		buf = malloc(sizeof(*buf));
		if (!buf)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		res = util_key_desc_set_key(key, buf);
		if (res == ERR_CODE(PASSED))
			res = util_key_read_descriptor(key, NULL, 0, oargs);
	}

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

/**
 * kdf_tls12_end() - Finalize the TLS 1.2 operation
 * @args: SMW's Key derivation arguments
 * @key_derived: Key derived result
 * @key_identifiers: Test key identifiers list
 * @params: Pointer to json parameters
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
int kdf_tls12_end(struct smw_derive_key_args *args,
		  struct keypair_ops *key_derived,
		  struct key_identifier_list **key_identifiers,
		  json_object *params)
{
	int res;
	json_object *oargs = NULL;
	int key_id;
	struct keypair_ops key_test = { 0 };
	struct smw_kdf_tls12_args *tls_args;

	if (!args || !params || !args->kdf_arguments) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	tls_args = args->kdf_arguments;

	/* Registers all generated keys in the test key identifiers list */
	res = util_read_json_type(&oargs, OP_ARGS_OBJ, t_object, params);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!oargs)
		return ERR_CODE(MISSING_PARAMS);

	/* Even if it should not occur at this stage, check oargs */
	if (kdf_tls12_is_mac_key_expected(tls_args->encryption_name)) {
		res = util_read_json_type(&key_id, "client_w_mac_key_id", t_int,
					  oargs);
		if (res != ERR_CODE(PASSED))
			return res;

		key_test.desc.id = tls_args->client_w_mac_key_id;
		res = util_key_add_node(key_identifiers, key_id, &key_test);
		if (res != ERR_CODE(PASSED))
			return res;

		res = util_read_json_type(&key_id, "server_w_mac_key_id", t_int,
					  oargs);
		if (res != ERR_CODE(PASSED))
			return res;

		key_test.desc.id = tls_args->server_w_mac_key_id;
		res = util_key_add_node(key_identifiers, key_id, &key_test);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	res = util_read_json_type(&key_id, "client_w_enc_key_id", t_int, oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	key_test.desc.id = tls_args->client_w_enc_key_id;
	res = util_key_add_node(key_identifiers, key_id, &key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&key_id, "server_w_enc_key_id", t_int, oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	key_test.desc.id = tls_args->server_w_enc_key_id;
	res = util_key_add_node(key_identifiers, key_id, &key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&key_id, "master_sec_key_id", t_int, oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	key_test.desc.id = tls_args->master_sec_key_id;
	res = util_key_add_node(key_identifiers, key_id, &key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&oargs, OP_OUTPUT_OBJ, t_object, params);
	if (res == ERR_CODE(PASSED) && oargs) {
		res = util_read_json_type(&key_id, "key_id", t_int, oargs);
		if (res != ERR_CODE(PASSED))
			return res;

		res = util_key_add_node(key_identifiers, key_id, key_derived);
		if (res != ERR_CODE(PASSED))
			return res;
	}

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
	int (*read_args)(void **kdf_args, json_object *oargs);
	int (*prepare_result)(struct keypair_ops *key, json_object *params);
	int (*end_operation)(struct smw_derive_key_args *args,
			     struct keypair_ops *key_derived,
			     struct key_identifier_list **key_identifiers,
			     json_object *params);
	void (*free)(struct smw_derive_key_args *args);
} kdf_ops[] = { {
			.name = "TLS12_KEY_EXCHANGE",
			.read_args = &kdf_tls12_args_read,
			.prepare_result = &kdf_tls12_prepare_result,
			.end_operation = &kdf_tls12_end,
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
static int kdf_args_read(struct smw_derive_key_args *args, json_object *params)
{
	int res;

	const struct kdf_op *kdf_op;
	json_object *oargs = NULL;

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
 * @args: Pointer to SMW's derive key arguments
 * @params: Pointer to json parameters
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
static int setup_derive_opt_params(struct smw_derive_key_args *args,
				   json_object *params)
{
	int res;

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args->key_attributes_list,
				  &args->key_attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read (if any) the key derivation function name and arguments */
	res = kdf_args_read(args, params);

	return res;
}

/**
 * setup_derive_output() - Setup the key derivation output arguments.
 * @args: Pointer to SMW's derive key arguments
 * @key: Test keypair operation's result
 * @params: Pointer to json parameters
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int setup_derive_output(struct smw_derive_key_args *args,
			       struct keypair_ops *key, json_object *params)
{
	int res = ERR_CODE(PASSED);

	const struct kdf_op *kdf_op;
	json_object *oargs = NULL;

	kdf_op = get_kdf_op(args->kdf_name);

	if (kdf_op && kdf_op->prepare_result) {
		res = util_read_json_type(&oargs, OP_OUTPUT_OBJ, t_object,
					  params);
		if (res == ERR_CODE(PASSED) && oargs)
			res = kdf_op->prepare_result(key, oargs);
	}

	return res;
}

/**
 * setup_derive_base() - Setup the key derivation base argument.
 * @params: Pointer to json parameters.
 * @key_identifiers: Test key identifiers list.
 * @key_base: Test keypair operation's base.
 * @base_buffer: Pointer to base keypair buffer structure.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -FAILED                  - Error in definition file
 */
static int setup_derive_base(json_object *params,
			     struct key_identifier_list *key_identifiers,
			     struct keypair_ops *key_base,
			     struct smw_keypair_buffer *base_buffer)
{
	int res = ERR_CODE(FAILED);
	int status;
	int key_id = INT_MAX;
	json_object *base_args = NULL;

	res = util_read_json_type(&base_args, OP_INPUT_OBJ, t_object, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/*
	 * Initialize key descriptor of the key base
	 * No key buffer and type of key unknown
	 */
	res = util_key_desc_init(key_base, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(key_base, &key_id, 0, base_args);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_id != INT_MAX) {
		/* Key ID is defined, try to find it */
		res = util_key_find_key_node(key_identifiers, key_id, key_base);
		if (res != ERR_CODE(PASSED))
			return res;

		/*
		 * If Security size is not set get it from the SMW key
		 * identifier
		 */
		if (!util_key_is_security_set(key_base)) {
			status = smw_get_security_size(&key_base->desc);
			if (status != SMW_STATUS_OK)
				res = ERR_CODE(BAD_RESULT);
		}
	} else {
		/*
		 * Key ID not set, read the key base buffer from test
		 * definition file.
		 */
		res = util_key_desc_set_key(key_base, base_buffer);
		if (res == ERR_CODE(PASSED))
			res = util_key_read_descriptor(key_base, NULL, 0,
						       base_args);
	}

	return res;
}

/**
 * end_derive_operation() - End key derivation operations.
 * @args: Pointer to SMW's derive key arguments
 * @key_derived: Key derived result
 * @key_identifiers: Test key identifiers list
 * @params: Pointer to json parameters
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int end_derive_operation(struct smw_derive_key_args *args,
				struct keypair_ops *key_derived,
				struct key_identifier_list **key_identifiers,
				json_object *params)
{
	int res = ERR_CODE(FAILED);

	const struct kdf_op *kdf_op;

	kdf_op = get_kdf_op(args->kdf_name);

	if (kdf_op && kdf_op->end_operation)
		res = kdf_op->end_operation(args, key_derived, key_identifiers,
					    params);

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

static int derive_bad_params(json_object *params,
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

	case FAKE_KEY_ID:
		(*args)->key_descriptor_base->id = FAKE_KEY_ID_NIST_256_0_ID;
		break;

	case TLS12_KDF_ARGS_NULL:
		(*args)->kdf_name = "TLS12_KEY_EXCHANGE";
		(*args)->kdf_arguments = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int derive_key(json_object *params, struct common_parameters *common_params,
	       struct key_identifier_list **key_identifiers,
	       enum smw_status_code *ret_status)
{
	int res = ERR_CODE(FAILED);
	struct keypair_ops key_base = { 0 };
	struct keypair_ops key_derived = { 0 };
	struct smw_keypair_buffer base_buffer = { 0 };
	struct smw_derive_key_args args = { 0 };
	struct smw_derive_key_args *smw_args = &args;

	if (!params || !key_identifiers || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;

	if (common_params->subsystem &&
	    !strcmp(common_params->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = common_params->subsystem;

	args.key_descriptor_base = &key_base.desc;
	args.key_descriptor_derived = &key_derived.desc;

	/* Setup key descitpor or the key base */
	res = setup_derive_base(params, *key_identifiers, &key_base,
				&base_buffer);
	if (res != ERR_CODE(PASSED) && !common_params->is_api_test)
		goto exit;

	/* Setup optional parameters */
	res = setup_derive_opt_params(&args, params);
	if (res != ERR_CODE(PASSED) && !common_params->is_api_test)
		goto exit;

	/*
	 * Initialize key descriptor of the key derived
	 * No key buffer and type of key unknown
	 */
	res = util_key_desc_init(&key_derived, NULL);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Setup the output arguments */
	res = setup_derive_output(&args, &key_derived, params);
	if (res != ERR_CODE(PASSED) && !common_params->is_api_test)
		goto exit;

	res = derive_bad_params(params, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	*ret_status = smw_derive_key(smw_args);
	if (CHECK_RESULT(*ret_status, common_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

	if (*ret_status == SMW_STATUS_OK)
		res = end_derive_operation(&args, &key_derived, key_identifiers,
					   params);

exit:
	util_key_free_key(&key_base);

	/*
	 * Don't free key data if it's present in key identifiers linked list
	 * (ephemeral keys)
	 */
	if (util_key_is_id_set(&key_derived))
		util_key_free_key(&key_derived);

	kdf_args_free(&args);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}
