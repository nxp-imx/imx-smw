// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_keymgr.h>
#include <smw/names.h>
#include <smw/crypto/op_context.h>

#include "util.h"
#include "util_key.h"
#include "util_context.h"

#include "key.h"
#include "keymgr.h"
#include "hash.h"

enum hkdf_step {
	HKDF_STEP_INVALID,
	/* HKDF step 1 expand */
	HKDF_STEP_EXPAND,
	/* HKDF step 2 extract */
	HKDF_STEP_EXTRACT,
	/* HKDF Step 1 and step 2 combined */
	HKDF_STEP_FULL
};

#define KDF_NAME(_name)                                                        \
	{                                                                      \
		.name = SMW_KDF_NAME_##_name, .string = #_name                 \
	}

static struct {
	smw_kdf_t name;
	const char *string;
} kdf_names[] = { KDF_NAME(HKDF), KDF_NAME(TLS12_KEY_EXCHANGE), KDF_NAME(ECDH),
		  KDF_NAME(TLS12_OP_KEY_EXCHANGE) };

#define KEA(_name)                                                             \
	{                                                                      \
		.name = SMW_TLS12_KEA_NAME_##_name, .string = #_name           \
	}

static struct {
	smw_tls12_kea_t name;
	const char *string;
} key_exchange_names[] = { KEA(DH_DSS),	     KEA(DH_RSA),     KEA(DHE_DSS),
			   KEA(DHE_RSA),     KEA(ECDH_ECDSA), KEA(ECDH_RSA),
			   KEA(ECDHE_ECDSA), KEA(ECDHE_RSA),  KEA(RSA) };

#define ENC(_name)                                                             \
	{                                                                      \
		.name = SMW_TLS12_ENC_NAME_##_name, .string = #_name           \
	}

static struct {
	smw_tls12_enc_t name;
	const char *string;
} encryption_names[] = { ENC(NONE),	   ENC(3DES_EDE_CBC),
			 ENC(AES_128_CBC), ENC(AES_128_CCM),
			 ENC(AES_128_GCM), ENC(RC4_128),
			 ENC(AES_256_CBC), ENC(AES_256_CCM),
			 ENC(AES_256_GCM), ENC(CHACHA20_POLY1305) };

#define OP(_name)                                                              \
	{                                                                      \
		.name = SMW_TLS12_OP_NAME_##_name, .string = #_name            \
	}
static struct {
	smw_tls12_op_t name;
	const char *string;
} op_names[] = { OP(NONE), OP(MASTER_SECRET), OP(KEY_EXPANSION) };

static smw_kdf_t get_kdf_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_KDF_NAME_NONE;

	for (; i < ARRAY_SIZE(kdf_names); i++) {
		if (!strcmp(kdf_names[i].string, string))
			return kdf_names[i].name;
	}

	return SMW_KDF_NAME_NB + 1;
}

static smw_tls12_kea_t get_tls12_key_exchange_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_TLS12_KEA_NAME_NONE;

	for (; i < ARRAY_SIZE(key_exchange_names); i++) {
		if (!strcmp(key_exchange_names[i].string, string))
			return key_exchange_names[i].name;
	}

	return SMW_TLS12_KEA_NAME_NB + 1;
}

static smw_tls12_enc_t get_tls12_encryption_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_TLS12_ENC_NAME_NONE;

	for (; i < ARRAY_SIZE(encryption_names); i++) {
		if (!strcmp(encryption_names[i].string, string))
			return encryption_names[i].name;
	}

	return SMW_TLS12_ENC_NAME_NB + 1;
}

static smw_tls12_op_t get_tls12_operation_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_TLS12_OP_NAME_NONE;

	for (; i < ARRAY_SIZE(op_names); i++) {
		if (!strcmp(op_names[i].string, string))
			return op_names[i].name;
	}

	return SMW_TLS12_OP_NAME_NB;
}

/**
 * read_derived_key_descriptor() - Read the derived key descriptor definition
 * @keys: Keys list.
 * @derived_key_desc: Pointer to derived key descriptor structure.
 * @key_name: Key name.
 *
 * Read the test definition to extract SMW derived key descriptor fields
 * (key type, security size, format, key buffer etc.), if defined.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
static int
read_derived_key_descriptor(struct llist *keys,
			    struct smw_derived_key_descriptor *derived_key_desc,
			    const char *key_name)
{
	int ret = ERR_CODE(PASSED);
	struct key_data *data = NULL;
	const char *type_string = NULL;
	const char *format_string = NULL;

	if (!derived_key_desc || !key_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	/* Read 'type' parameter if defined */
	ret = util_read_json_type(&type_string, TYPE_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	derived_key_desc->type_name = key_get_type_name(type_string);

	/* Read 'security_size' parameter if defined */
	ret = util_read_json_type(&derived_key_desc->security_size,
				  SEC_SIZE_OBJ, t_int, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'id' parameter if defined */
	ret = util_read_json_type(&derived_key_desc->id, ID_OBJ, t_uint,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'format' parameter if defined */
	ret = util_read_json_type(&format_string, FORMAT_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	derived_key_desc->format_name = key_get_format_name(format_string);

	/* Read shared secret buffer if defined */
	ret = util_read_obj_value(&derived_key_desc->shared_secret,
				  &derived_key_desc->shared_secret_len,
				  SHARED_SECRET_OBJ, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read OKM buffer");
		return ret;
	}

	return ERR_CODE(PASSED);
}

/**
 * key_prepare_derived_key_data() - Fill key data structure for derived key
 * @key: Derived key descriptor structure
 * @key_data: Key data to save
 */
static void key_prepare_derived_key_data(struct smw_derived_key_descriptor *key,
					 struct key_data *key_data)
{
	key_data->identifier = key->id;

	if (key->shared_secret) {
		key_data->pub_key.data = key->shared_secret;
		key_data->pub_key.length = key->shared_secret_len;
	}
}

/**
 * setup_derive_base() - Setup the key derivation base argument.
 * @subtest: Subtest data.
 * @key_base: Test keypair operations.
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
	res = key_desc_init(key_base, base_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&key_name, OP_INPUT_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), key_base, key_name);

	return res;
}

/**
 * read_prk_descriptor() - Read PRK descriptor definition
 * @subtest: Subtest data
 * @key_test: Test keypair operations.
 * @key_buffer: Pointer to base keypair buffer structure.
 *
 * Read the test definition to extract PRK descriptor field key format, if
 * defined.
 * Read PRK ID/ buffer stored from the key linked list.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
static int setup_prk_descriptor(struct subtest_data *subtest,
				struct keypair_ops *key_test,
				struct smw_keypair_buffer *key_buffer)
{
	int ret = ERR_CODE(PASSED);
	struct key_data *data = NULL;
	const char *key_name = NULL;
	const char *format_string = NULL;
	const char *type_string = NULL;
	struct smw_key_descriptor *prk_desc = NULL;

	prk_desc = &key_test->desc;

	ret = util_read_json_type(&key_name, OP_INPUT_OBJ, t_string,
				  subtest->params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!prk_desc || !key_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_list_find_node(list_keys(subtest), (uintptr_t)key_name,
				  (void **)&data);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	/* Initialize key descriptor */
	ret = key_desc_init(key_test, key_buffer);
	if (ret != ERR_CODE(PASSED))
		return ret;

	/* Read 'format' parameter if defined */
	ret = util_read_json_type(&format_string, FORMAT_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	key_buffer->format_name = key_get_format_name(format_string);

	/* Read PRK Type name, if set */
	ret = util_read_json_type(&type_string, TYPE_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	prk_desc->type_name = key_get_type_name(type_string);

	/* Read PRK ID, if set */
	ret = util_read_json_type(&prk_desc->id, ID_OBJ, t_uint,
				  data->okey_params);
	if (ret == ERR_CODE(PASSED))
		goto end;

	/* Read public key buffer, if any */
	ret = util_read_obj_value(key_public_data(key_test),
				  key_public_length(key_test), PUB_KEY_OBJ,
				  data->okey_params);
	if (ret == ERR_CODE(PASSED)) {
		prk_desc->type_name = SMW_KEY_TYPE_NAME_RAW;
		goto end;
	}

	/* If the PRK ID or public key buffer are not defined in the test
	 * definition, fetch the PRK ID or public key buffer from the
	 * key linked list.
	 */
	if (data->identifier) {
		prk_desc->id = data->identifier;
	} else if (data->pub_key.data) {
		prk_desc->buffer->format_name =
			key_get_format_name(format_string);
		prk_desc->type_name = SMW_KEY_TYPE_NAME_RAW;

		*key_public_length(key_test) = data->pub_key.length;
		*key_public_data(key_test) = malloc(data->pub_key.length);
		if (!*key_public_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(*key_public_data(key_test), data->pub_key.data,
		       data->pub_key.length);
	}

end:
	return ERR_CODE(PASSED);
}

/**
 * kdf_tls12_setup_base_key() - Setup the base key for key derivation operation.
 * @subtest: Subtest data.
 * @args: Pointer to public key derivation argument structure.
 * @key_base: Test keypair operations.
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
static int kdf_tls12_setup_base_key(struct subtest_data *subtest,
				    struct smw_derive_key_args *args,
				    struct keypair_ops *key_base,
				    struct smw_keypair_buffer *base_buffer)
{
	int res = ERR_CODE(PASSED);
	(void)args;

	res = setup_derive_base(subtest, key_base, base_buffer);

	return res;
}

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
static int kdf_tls12_read_args(void **kdf_args, struct subtest_data *subtest,
			       struct json_object *oargs)
{
	(void)subtest;

	int res = ERR_CODE(BAD_ARGS);
	const char *prf_string = NULL;
	struct tbuffer buf = { 0 };

	struct smw_kdf_tls12_args *tls_args = NULL;
	const char *key_exchange_string = NULL;
	const char *encryption_string = NULL;

	if (!kdf_args || !oargs) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	tls_args = calloc(1, sizeof(*tls_args));
	if (!tls_args)
		return INTERNAL_OUT_OF_MEMORY;

	res = util_read_json_type(&key_exchange_string, KEY_EXCHANGE_NAME_OBJ,
				  t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->key_exchange_name =
		get_tls12_key_exchange_name(key_exchange_string);

	res = util_read_json_type(&encryption_string, ENCRYPTION_NAME_OBJ,
				  t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->encryption_name =
		get_tls12_encryption_name(encryption_string);

	res = util_read_json_type(&prf_string, PRF_NAME_OBJ, t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->prf_name = hash_get_algo_name(prf_string);

	res = UTIL_READ_JSON_ST_FIELD(tls_args, ext_master_key, boolean, oargs);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = util_read_json_type(&buf, KDF_INPUT_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->kdf_input = buf.data;
	tls_args->kdf_input_length = buf.length;

	buf.data = NULL;
	buf.length = 0;

	res = util_read_json_type(&buf, CLIENT_WRITE_IV_OBJ, t_buffer_hex,
				  oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->client_w_iv = buf.data;
	tls_args->client_w_iv_length = buf.length;

	buf.data = NULL;
	buf.length = 0;

	res = util_read_json_type(&buf, SERVER_WRITE_IV_OBJ, t_buffer_hex,
				  oargs);
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

		if (tls_args->client_w_iv)
			free(tls_args->client_w_iv);

		if (tls_args->server_w_iv)
			free(tls_args->server_w_iv);

		free(tls_args);
	}

	return res;
}

static void kdf_tls12_op_free_random_data(struct smw_kdf_tls12_random_data *rd)
{
	if (!rd)
		return;

	if (rd->client_random)
		free(rd->client_random);

	if (rd->server_random)
		free(rd->server_random);

	free(rd);
}

static void
kdf_tls12_op_free_master_secret(struct smw_kdf_tls12_op_args *tls_args)
{
	struct smw_kdf_tls12_session_hash *sh = NULL;
	struct smw_kdf_tls12_random_data *rd = NULL;

	if (tls_args->master_secret.ext_master_key) {
		sh = tls_args->master_secret.session_hash;
		if (sh) {
			if (sh->hash)
				free(sh->hash);

			free(sh);
		}
	} else {
		rd = tls_args->master_secret.random_data;
		kdf_tls12_op_free_random_data(rd);
	}

	if (tls_args->master_secret.peer_public_buffer)
		free(tls_args->master_secret.peer_public_buffer);
}

static void
kdf_tls12_op_free_key_expansion(struct smw_kdf_tls12_op_args *tls_args)
{
	kdf_tls12_op_free_random_data(tls_args->key_expansion.random_data);

	if (tls_args->key_expansion.client_w_iv)
		free(tls_args->key_expansion.client_w_iv);

	if (tls_args->key_expansion.server_w_iv)
		free(tls_args->key_expansion.server_w_iv);
}

static int
kdf_tls12_op_read_master_secret(struct smw_kdf_tls12_op_args *tls_args,
				struct json_object *oargs)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *osession_hash = NULL;
	struct json_object *orandom_data = NULL;
	const char *key_exchange_string = NULL;
	bool ext_master_key = false;
	struct smw_kdf_tls12_session_hash *sh = NULL;
	struct smw_kdf_tls12_random_data *rd = NULL;
	struct tbuffer buf = { 0 };

	res = util_read_json_type(&tls_args->master_secret.version, VERSION_OBJ,
				  t_int8, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = util_read_json_type(&key_exchange_string, KEY_EXCHANGE_NAME_OBJ,
				  t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->master_secret.key_exchange_name =
		get_tls12_key_exchange_name(key_exchange_string);

	res = util_read_json_type(&ext_master_key, EXT_MASTER_KEY_OBJ,
				  t_boolean, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->master_secret.ext_master_key = ext_master_key;

	if (ext_master_key) {
		sh = calloc(1, sizeof(*sh));
		if (!sh) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}

		tls_args->master_secret.session_hash = sh;

		res = util_read_json_type(&osession_hash, SESSION_HASH_OBJ,
					  t_object, oargs);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;

		if (osession_hash) {
			res = util_read_json_type(&sh->version, VERSION_OBJ,
						  t_int8, osession_hash);
			if (res != ERR_CODE(PASSED) &&
			    res != ERR_CODE(VALUE_NOTFOUND))
				goto end;

			res = util_read_json_type(&buf, HASH_OBJ, t_buffer_hex,
						  osession_hash);
			if (res != ERR_CODE(PASSED) &&
			    res != ERR_CODE(VALUE_NOTFOUND))
				goto end;
		}

		sh->hash = buf.data;
		sh->hash_length = buf.length;

		buf.data = NULL;
		buf.length = 0;
	} else {
		rd = calloc(1, sizeof(*rd));
		if (!rd) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}

		tls_args->master_secret.random_data = rd;

		res = util_read_json_type(&orandom_data, RANDOM_DATA_OBJ,
					  t_object, oargs);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;

		if (orandom_data) {
			res = util_read_json_type(&rd->version, VERSION_OBJ,
						  t_int8, orandom_data);
			if (res != ERR_CODE(PASSED) &&
			    res != ERR_CODE(VALUE_NOTFOUND))
				goto end;

			res = util_read_json_type(&buf, CLIENT_RANDOM_OBJ,
						  t_buffer_hex, orandom_data);
			if (res != ERR_CODE(PASSED) &&
			    res != ERR_CODE(VALUE_NOTFOUND))
				goto end;
		}

		rd->client_random = buf.data;
		rd->client_random_length = buf.length;

		buf.data = NULL;
		buf.length = 0;

		if (orandom_data) {
			res = util_read_json_type(&buf, SERVER_RANDOM_OBJ,
						  t_buffer_hex, orandom_data);
			if (res != ERR_CODE(PASSED) &&
			    res != ERR_CODE(VALUE_NOTFOUND))
				goto end;
		}

		rd->server_random = buf.data;
		rd->server_random_length = buf.length;

		buf.data = NULL;
		buf.length = 0;
	}

	res = util_read_json_type(&buf, PEER_PUB_KEY_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->master_secret.peer_public_buffer = buf.data;
	tls_args->master_secret.peer_public_buffer_length = buf.length;

	res = ERR_CODE(PASSED);

end:
	if (res != ERR_CODE(PASSED))
		kdf_tls12_op_free_master_secret(tls_args);

	return res;
}

static int
kdf_tls12_op_read_key_expansion(struct smw_kdf_tls12_op_args *tls_args,
				struct json_object *oargs)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *orandom_data = NULL;
	const char *encryption_string = NULL;
	struct smw_kdf_tls12_random_data *rd = NULL;
	struct tbuffer buf = { 0 };

	res = util_read_json_type(&tls_args->key_expansion.version, VERSION_OBJ,
				  t_int8, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = util_read_json_type(&encryption_string, ENCRYPTION_NAME_OBJ,
				  t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->key_expansion.encryption_name =
		get_tls12_encryption_name(encryption_string);

	rd = calloc(1, sizeof(*rd));
	if (!rd) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	tls_args->key_expansion.random_data = rd;

	res = util_read_json_type(&orandom_data, RANDOM_DATA_OBJ, t_object,
				  oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (orandom_data) {
		res = util_read_json_type(&rd->version, VERSION_OBJ, t_int8,
					  orandom_data);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;

		res = util_read_json_type(&buf, CLIENT_RANDOM_OBJ, t_buffer_hex,
					  orandom_data);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;
	}

	rd->client_random = buf.data;
	rd->client_random_length = buf.length;
	buf.data = NULL;
	buf.length = 0;

	if (orandom_data) {
		res = util_read_json_type(&buf, SERVER_RANDOM_OBJ, t_buffer_hex,
					  orandom_data);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;
	}

	rd->server_random = buf.data;
	rd->server_random_length = buf.length;
	buf.data = NULL;
	buf.length = 0;

	res = util_read_json_type(&buf, CLIENT_WRITE_IV_OBJ, t_buffer_hex,
				  oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->key_expansion.client_w_iv = buf.data;
	tls_args->key_expansion.client_w_iv_length = buf.length;
	buf.data = NULL;
	buf.length = 0;

	res = util_read_json_type(&buf, SERVER_WRITE_IV_OBJ, t_buffer_hex,
				  oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->key_expansion.server_w_iv = buf.data;
	tls_args->key_expansion.server_w_iv_length = buf.length;

	res = ERR_CODE(PASSED);

end:
	if (res != ERR_CODE(PASSED))
		kdf_tls12_op_free_key_expansion(tls_args);

	return res;
}

static int kdf_tls12_op_read_args(void **kdf_args, struct subtest_data *subtest,
				  struct json_object *oargs)
{
	int res = ERR_CODE(BAD_ARGS);
	const char *prf_string = NULL;
	const char *op_string = NULL;
	unsigned int ctx_id = UINT_MAX;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;
	enum arguments_test_err_case error = NOT_DEFINED;

	struct smw_kdf_tls12_op_args *tls_args = NULL;

	if (!kdf_args || !oargs) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	tls_args = calloc(1, sizeof(*tls_args));
	if (!tls_args)
		return INTERNAL_OUT_OF_MEMORY;

	*kdf_args = tls_args;

	res = util_read_test_error(&error, subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	if (error == CTX_NULL) {
		tls_args->context = NULL;
	} else {
		res = util_context_set_op_ctx(subtest, &ctx_id,
					      &tls_args->context, api_ctx);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	res = util_read_json_type(&tls_args->version, VERSION_OBJ, t_int8,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = util_read_json_type(&op_string, OP_NAME_OBJ, t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->op_name = get_tls12_operation_name(op_string);

	res = util_read_json_type(&prf_string, PRF_NAME_OBJ, t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	tls_args->prf_name = hash_get_algo_name(prf_string);

	if (tls_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET)
		res = kdf_tls12_op_read_master_secret(tls_args, oargs);
	else if (tls_args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION)
		res = kdf_tls12_op_read_key_expansion(tls_args, oargs);

end:
	if (res != ERR_CODE(PASSED)) {
		if (tls_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET) {
			kdf_tls12_op_free_master_secret(tls_args);
		} else if (tls_args->op_name ==
			   SMW_TLS12_OP_NAME_KEY_EXPANSION) {
			kdf_tls12_op_free_key_expansion(tls_args);
		}

		free(tls_args);
	}

	return res;
}

/**
 * kdf_tls12_prepare_result() - Prepare the TLS 1.2 results
 * @subtest: Subtest data
 * @args: Pointer to public key derivation argument structure
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_tls12_prepare_result(struct subtest_data *subtest,
				    struct smw_derive_key_args *args)
{
	int res = ERR_CODE(PASSED);
	const char *key_name = NULL;
	struct smw_derived_key_descriptor *derived_key_desc = NULL;

	res = util_read_json_type(&key_name, OP_OUTPUT_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = key_read_attributes(subtest->params, &args->key_attributes);
	if (res != ERR_CODE(PASSED))
		return res;

	derived_key_desc = args->key_descriptor_derived;

	res = read_derived_key_descriptor(list_keys(subtest), derived_key_desc,
					  key_name);

	return res;
}

static void kdf_tls12_op_free(struct smw_derive_key_args *args)
{
	struct smw_kdf_tls12_op_args *tls_args = NULL;

	if (!args || !args->kdf_arguments)
		return;

	tls_args = args->kdf_arguments;

	if (tls_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET)
		kdf_tls12_op_free_master_secret(tls_args);
	else if (tls_args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION)
		kdf_tls12_op_free_key_expansion(tls_args);

	free(tls_args);
	args->kdf_arguments = NULL;
}

/**
 * kdf_tls12_is_mac_key_expected() - Return if MAC key is expected
 * @encryption_name: Name of the encryption algorithm
 *
 * Return:
 * True     - MAC key is expected
 * False    - MAC key is not expected
 */
static bool kdf_tls12_is_mac_key_expected(smw_tls12_enc_t encryption_name)
{
	/* Server and client MAC keys are only generated for CBC cipher mode */
	if (encryption_name == SMW_TLS12_ENC_NAME_3DES_EDE_CBC ||
	    encryption_name == SMW_TLS12_ENC_NAME_AES_128_CBC ||
	    encryption_name == SMW_TLS12_ENC_NAME_AES_256_CBC)
		return true;

	return false;
}

static int store_key_data(struct llist *keys, const char *key,
			  struct key_data *key_data, struct json_object *params)
{
	int res = ERR_CODE(BAD_ARGS);
	const char *key_name = NULL;

	if (!key || !key_data || !params) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&key_name, key, t_string, params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_key_update_node(keys, key_name, key_data);

	return res;
}

/**
 * kdf_tls12_end_operation() - Finalize the TLS 1.2 operation
 * @subtest: Subtest data
 * @args: SMW's Key derivation arguments
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_tls12_end_operation(struct subtest_data *subtest,
				   struct smw_derive_key_args *args)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *oargs = NULL;
	struct key_data key_data = { 0 };
	struct smw_kdf_tls12_args *tls_args = NULL;
	struct llist *keys = NULL;

	if (!args || !subtest || !args->kdf_arguments) {
		DBG_PRINT_BAD_ARGS();
		return res;
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

	key_data.identifier = tls_args->master_sec_key_id;
	res = store_key_data(keys, MASTER_SEC_KEY_NAME_OBJ, &key_data, oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Even if it should not occur at this stage, check oargs */
	if (kdf_tls12_is_mac_key_expected(tls_args->encryption_name)) {
		key_data.identifier = tls_args->client_w_mac_key_id;
		res = store_key_data(keys, CLIENT_W_MAC_KEY_NAME_OBJ, &key_data,
				     oargs);
		if (res != ERR_CODE(PASSED))
			return res;

		key_data.identifier = tls_args->server_w_mac_key_id;
		res = store_key_data(keys, SERVER_W_MAC_KEY_NAME_OBJ, &key_data,
				     oargs);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	key_data.identifier = tls_args->client_w_enc_key_id;
	res = store_key_data(keys, CLIENT_W_ENC_KEY_NAME_OBJ, &key_data, oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	key_data.identifier = tls_args->server_w_enc_key_id;
	res = store_key_data(keys, SERVER_W_ENC_KEY_NAME_OBJ, &key_data, oargs);
	if (res != ERR_CODE(PASSED))
		return res;

	key_prepare_derived_key_data(args->key_descriptor_derived, &key_data);
	res = store_key_data(keys, OP_OUTPUT_OBJ, &key_data, subtest->params);

	return res;
}

/**
 * kdf_tls12_end_operation() - Finalize the TLS 1.2 operation
 * @subtest: Subtest data
 * @args: SMW's Key derivation arguments
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_tls12_op_end_operation(struct subtest_data *subtest,
				      struct smw_derive_key_args *args)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *oargs = NULL;
	struct key_data key_data = { 0 };
	struct smw_kdf_tls12_op_args *tls_args = NULL;
	struct smw_kdf_tls12_key_expansion_args *ke = NULL;
	struct llist *keys = NULL;

	if (!args || !subtest || !args->kdf_arguments) {
		DBG_PRINT_BAD_ARGS();
		return res;
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

	if (tls_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET) {
		key_prepare_derived_key_data(args->key_descriptor_derived,
					     &key_data);
		res = store_key_data(keys, OP_OUTPUT_OBJ, &key_data,
				     subtest->params);
	} else if (tls_args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION) {
		ke = &tls_args->key_expansion;

		if (kdf_tls12_is_mac_key_expected(ke->encryption_name)) {
			key_data.identifier = ke->client_w_mac_key_id;
			res = store_key_data(keys, CLIENT_W_MAC_KEY_NAME_OBJ,
					     &key_data, oargs);
			if (res != ERR_CODE(PASSED))
				return res;

			key_data.identifier = ke->server_w_mac_key_id;
			res = store_key_data(keys, SERVER_W_MAC_KEY_NAME_OBJ,
					     &key_data, oargs);
			if (res != ERR_CODE(PASSED))
				return res;
		}

		key_data.identifier = ke->client_w_enc_key_id;
		res = store_key_data(keys, CLIENT_W_ENC_KEY_NAME_OBJ, &key_data,
				     oargs);
		if (res != ERR_CODE(PASSED))
			return res;

		key_data.identifier = ke->server_w_enc_key_id;
		res = store_key_data(keys, SERVER_W_ENC_KEY_NAME_OBJ, &key_data,
				     oargs);
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
	struct smw_kdf_tls12_args *tls_args = NULL;

	if (args) {
		if (args->kdf_arguments) {
			tls_args = args->kdf_arguments;

			if (tls_args->kdf_input)
				free(tls_args->kdf_input);

			if (tls_args->client_w_iv)
				free(tls_args->client_w_iv);

			if (tls_args->server_w_iv)
				free(tls_args->server_w_iv);

			free(args->kdf_arguments);
			args->kdf_arguments = NULL;
		}
	}
}

/**
 * compare_output() - Compare received output with expected output
 * @received_output: Pointer to received output buffer
 * @received_output_len: Length of @received_output
 * @expected_output: Pointer to expected output buffer
 * @expected_output_len: Length of @expected_output
 *
 * Return:
 * PASSED - Success
 * Error code from util_compare_buffers
 */
static int compare_output(unsigned char *received_output,
			  unsigned int received_output_len,
			  unsigned char *expected_output,
			  unsigned int expected_output_len)
{
	int res = ERR_CODE(PASSED);

	if (received_output && expected_output)
		res = util_compare_buffers(received_output, received_output_len,
					   expected_output,
					   expected_output_len);

	return res;
}

/**
 * get_hkdf_step() - Return HKDF step.
 * @args: Pointer to public Key derivation arguments structure
 *
 * Return:
 * HKDF step
 */
static int get_hkdf_step(struct smw_derive_key_args *args)
{
	enum hkdf_step step = HKDF_STEP_INVALID;
	struct smw_kdf_hkdf_args *hkdf_args = NULL;

	if (args && args->kdf_arguments) {
		hkdf_args = args->kdf_arguments;
		if (!hkdf_args->extract && hkdf_args->expand)
			step = HKDF_STEP_EXPAND;
		else if (!hkdf_args->expand && hkdf_args->extract)
			step = HKDF_STEP_EXTRACT;
		else if (hkdf_args->expand && hkdf_args->extract)
			step = HKDF_STEP_FULL;
	}

	return step;
}

/**
 * kdf_hkdf_setup_base_key() - Setup the base key for HKDF.
 * @subtest: Subtest data.
 * @args: Pointer to public key derivation argument structure.
 * @key_base: Test keypair operations.
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
static int kdf_hkdf_setup_base_key(struct subtest_data *subtest,
				   struct smw_derive_key_args *args,
				   struct keypair_ops *key_base,
				   struct smw_keypair_buffer *base_buffer)
{
	int res = ERR_CODE(PASSED);

	enum hkdf_step step = HKDF_STEP_INVALID;

	if (!args || !subtest || !base_buffer || !key_base) {
		DBG_PRINT_BAD_ARGS();
		res = ERR_CODE(BAD_ARGS);
		return res;
	}

	step = get_hkdf_step(args);
	if (step == HKDF_STEP_EXTRACT || step == HKDF_STEP_FULL)
		res = setup_derive_base(subtest, key_base, base_buffer);
	else if (step == HKDF_STEP_EXPAND)
		res = setup_prk_descriptor(subtest, key_base, base_buffer);

	return res;
}

/**
 * kdf_hkdf_read_args() - Read the HKDF function arguments
 * @kdf_args: SMW's HMAC-based Key derivation function arguments
 * @oargs: Reference to the test definition json-c arguments array
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
static int kdf_hkdf_read_args(void **kdf_args, struct subtest_data *subtest,
			      struct json_object *oargs)
{
	(void)subtest;

	int res = ERR_CODE(BAD_ARGS);

	struct tbuffer salt_buf = { 0 };
	struct tbuffer info_buf = { 0 };
	struct tbuffer peer_pub_buf = { 0 };
	const char *hash_string = NULL;
	char *hkdf_step = NULL;

	struct smw_kdf_hkdf_args *hkdf_args = NULL;
	enum hkdf_step step = HKDF_STEP_INVALID;

	if (!kdf_args || !oargs) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	hkdf_args = calloc(1, sizeof(*hkdf_args));
	if (!hkdf_args)
		return INTERNAL_OUT_OF_MEMORY;

	/* Get the Hash algorithm, if defined */
	res = util_read_json_type(&hash_string, ALGO_OBJ, t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	hkdf_args->hash_algo = hash_get_algo_name(hash_string);

	/* Get the HKDF step, if defined*/
	res = util_read_json_type(&hkdf_step, TYPE_OBJ, t_string, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (hkdf_step && (!strcmp(hkdf_step, "HKDF_EXPAND"))) {
		hkdf_args->expand = true;
		step = HKDF_STEP_EXPAND;
	} else if (hkdf_step && (!strcmp(hkdf_step, "HKDF_EXTRACT"))) {
		hkdf_args->extract = true;
		step = HKDF_STEP_EXTRACT;
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		hkdf_args->expand = true;
		hkdf_args->extract = true;
		step = HKDF_STEP_FULL;
	} else {
		res = ERR_CODE(BAD_ARGS);
		goto end;
	}

	/* Get info buffer, if defined */
	res = util_read_json_type(&info_buf, INFO_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read info buffer");
		goto end;
	}

	/* Get salt buffer, if defined */
	res = util_read_json_type(&salt_buf, SALT_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read salt buffer");
		goto end;
	}

	res = util_read_json_type(&peer_pub_buf, PEER_PUB_KEY_OBJ, t_buffer_hex,
				  oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read peer public buffer");
		goto end;
	}

	if (step == HKDF_STEP_FULL) {
		hkdf_args->hkdf_args.info = info_buf.data;
		hkdf_args->hkdf_args.info_len = info_buf.length;
		hkdf_args->hkdf_args.salt = salt_buf.data;
		hkdf_args->hkdf_args.salt_len = salt_buf.length;
		hkdf_args->hkdf_args.peer_public_buffer = peer_pub_buf.data;
		hkdf_args->hkdf_args.peer_public_buffer_len =
			peer_pub_buf.length;
	} else if (step == HKDF_STEP_EXTRACT) {
		hkdf_args->hkdf_extract_args.salt = salt_buf.data;
		hkdf_args->hkdf_extract_args.salt_len = salt_buf.length;
		hkdf_args->hkdf_extract_args.peer_public_buffer =
			peer_pub_buf.data;
		hkdf_args->hkdf_extract_args.peer_public_buffer_len =
			peer_pub_buf.length;
	} else if (step == HKDF_STEP_EXPAND) {
		hkdf_args->hkdf_expand_args.info = info_buf.data;
		hkdf_args->hkdf_expand_args.info_len = info_buf.length;
	}

	*kdf_args = hkdf_args;
	res = ERR_CODE(PASSED);

end:
	if (res != ERR_CODE(PASSED)) {
		if (salt_buf.data)
			free(salt_buf.data);

		if (info_buf.data)
			free(info_buf.data);

		if (peer_pub_buf.data)
			free(peer_pub_buf.data);

		if (hkdf_args)
			free(hkdf_args);
	}

	return res;
}

/**
 * kdf_hkdf_prepare_result() - Prepare the HKDF results
 * @subtest: Subtest data
 * @key: Derived key descriptor structure
 * @args: Pointer to public key derivation argument structure
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_hkdf_prepare_result(struct subtest_data *subtest,
				   struct smw_derive_key_args *args)
{
	int res = ERR_CODE(PASSED);

	const char *key_name = NULL;
	struct smw_derived_key_descriptor *key = NULL;
	struct json_object *okey_params = NULL;

	enum hkdf_step step = get_hkdf_step(args);

	if (step == HKDF_STEP_EXPAND || step == HKDF_STEP_FULL) {
		res = util_key_get_key_params(subtest, OP_OUTPUT_OBJ,
					      &okey_params);
		if (res != ERR_CODE(PASSED))
			return res;

		res = key_read_attributes(okey_params, &args->key_attributes);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	res = util_read_json_type(&key_name, OP_OUTPUT_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	key = args->key_descriptor_derived;

	res = read_derived_key_descriptor(list_keys(subtest), key, key_name);

	return res;
}

/**
 * kdf_hkdf_end_operation() - End key derivation operation and store derived key
 * @subtest: Subtest data
 * @args: SMW's Key derivation arguments
 * @key_derived: Key derived result
 *
 * Additionally, it checks if the shared secret data of derived key matches with
 * the expected shared secret buffer, if expected shared secret is set.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_hkdf_end_operation(struct subtest_data *subtest,
				  struct smw_derive_key_args *args)
{
	int res = ERR_CODE(BAD_ARGS);

	struct key_data key_data = { 0 };
	unsigned char *expected_okm = NULL;
	unsigned int expected_out_len = 0;
	struct tbuffer buf = { 0 };

	if (!args || !subtest || !args->kdf_arguments) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Read expected OKM buffer */
	res = util_read_json_type(&buf, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read expected shared secret buffer");
		return res;
	}

	expected_okm = buf.data;
	expected_out_len = buf.length;

	res = compare_output(args->key_descriptor_derived->shared_secret,
			     args->key_descriptor_derived->shared_secret_len,
			     expected_okm, expected_out_len);
	if (res)
		goto end;

	key_prepare_derived_key_data(args->key_descriptor_derived, &key_data);
	res = store_key_data(list_keys(subtest), OP_OUTPUT_OBJ, &key_data,
			     subtest->params);

end:
	if (buf.data)
		free(buf.data);

	return res;
}

/**
 * free_buffers() - Release memory allocated to buffers
 * @hkdf_args: Pointer to HMAC-based Key derivation function arguments
 *
 * Release info, salt or peer public key buffer based on HKDF step.
 *
 * Return:
 * None.
 */
static void free_buffers(struct smw_kdf_hkdf_args *hkdf_args)
{
	if (hkdf_args->expand && !hkdf_args->extract) {
		if (hkdf_args->hkdf_expand_args.info)
			free(hkdf_args->hkdf_expand_args.info);

	} else if (!hkdf_args->expand && hkdf_args->extract) {
		if (hkdf_args->hkdf_extract_args.salt)
			free(hkdf_args->hkdf_extract_args.salt);

		if (hkdf_args->hkdf_extract_args.peer_public_buffer)
			free(hkdf_args->hkdf_extract_args.peer_public_buffer);

	} else if (hkdf_args->expand && hkdf_args->extract) {
		if (hkdf_args->hkdf_args.info)
			free(hkdf_args->hkdf_args.info);

		if (hkdf_args->hkdf_args.salt)
			free(hkdf_args->hkdf_args.salt);

		if (hkdf_args->hkdf_args.peer_public_buffer)
			free(hkdf_args->hkdf_args.peer_public_buffer);
	}
}

/**
 * kdf_hkdf_free() - Free the HKDF operation arguments
 * @args: SMW's Key derivation arguments structure
 *
 * Return:
 * None.
 */
static void kdf_hkdf_free(struct smw_derive_key_args *args)
{
	struct smw_kdf_hkdf_args *hkdf_args = NULL;

	if (args) {
		if (args->kdf_arguments) {
			hkdf_args = args->kdf_arguments;

			free_buffers(hkdf_args);

			free(args->kdf_arguments);
			args->kdf_arguments = NULL;
		}
	}
}

/**
 * kdf_ecdh_setup_base_key() - Setup the base key for key derivation operation.
 * @subtest: Subtest data.
 * @args: Pointer to public key derivation argument structure.
 * @key_base: Test keypair operations.
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
static int kdf_ecdh_setup_base_key(struct subtest_data *subtest,
				   struct smw_derive_key_args *args,
				   struct keypair_ops *key_base,
				   struct smw_keypair_buffer *base_buffer)
{
	int res = ERR_CODE(PASSED);
	(void)args;

	res = setup_derive_base(subtest, key_base, base_buffer);

	return res;
}

/**
 * kdf_ecdh_read_args() - Read the ECDH function arguments
 * @kdf_args: SMW's ECDH arguments read
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
static int kdf_ecdh_read_args(void **kdf_args, struct subtest_data *subtest,
			      struct json_object *oargs)
{
	(void)subtest;

	int res = ERR_CODE(BAD_ARGS);
	struct tbuffer peer_pub_buf = { 0 };

	struct smw_kdf_ecdh_args *ecdh_args = NULL;

	if (!kdf_args || !oargs) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	ecdh_args = calloc(1, sizeof(*ecdh_args));
	if (!ecdh_args)
		return INTERNAL_OUT_OF_MEMORY;

	res = util_read_json_type(&peer_pub_buf, PEER_PUB_KEY_OBJ, t_buffer_hex,
				  oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read peer public buffer");
		goto end;
	}

	ecdh_args->peer_public_buffer = peer_pub_buf.data;
	ecdh_args->peer_public_buffer_length = peer_pub_buf.length;

	*kdf_args = ecdh_args;
	res = ERR_CODE(PASSED);

end:
	if (res != ERR_CODE(PASSED)) {
		if (peer_pub_buf.data)
			free(peer_pub_buf.data);

		if (ecdh_args)
			free(ecdh_args);
	}

	return res;
}

/**
 * kdf_ecdh_prepare_result() - Prepare the ECDH results
 * @subtest: Subtest data
 * @args: Pointer to public key derivation argument structure
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_ecdh_prepare_result(struct subtest_data *subtest,
				   struct smw_derive_key_args *args)
{
	int res = ERR_CODE(PASSED);
	const char *key_name = NULL;
	struct smw_derived_key_descriptor *derived_key_desc = NULL;
	struct json_object *okey_params = NULL;

	res = util_key_get_key_params(subtest, OP_OUTPUT_OBJ, &okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = key_read_attributes(okey_params, &args->key_attributes);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&key_name, OP_OUTPUT_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	derived_key_desc = args->key_descriptor_derived;

	res = read_derived_key_descriptor(list_keys(subtest), derived_key_desc,
					  key_name);

	return res;
}

/**
 * kdf_ecdh_end_operation() - Finalize the ECDH operation
 * @subtest: Subtest data
 * @args: SMW's Key derivation arguments
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND          - Value not found.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int kdf_ecdh_end_operation(struct subtest_data *subtest,
				  struct smw_derive_key_args *args)
{
	int res = ERR_CODE(BAD_ARGS);
	struct key_data key_data = { 0 };
	unsigned char *expected_okm = NULL;
	unsigned int expected_out_len = 0;
	struct tbuffer buf = { 0 };

	if (!args || !subtest || !args->kdf_arguments) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Read expected OKM buffer */
	res = util_read_json_type(&buf, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read expected shared secret buffer");
		return res;
	}

	expected_okm = buf.data;
	expected_out_len = buf.length;

	res = compare_output(args->key_descriptor_derived->shared_secret,
			     args->key_descriptor_derived->shared_secret_len,
			     expected_okm, expected_out_len);
	if (res)
		goto end;

	key_prepare_derived_key_data(args->key_descriptor_derived, &key_data);
	res = store_key_data(list_keys(subtest), OP_OUTPUT_OBJ, &key_data,
			     subtest->params);

end:
	if (buf.data)
		free(buf.data);

	return res;
}

/**
 * kdf_ecdh_free() - Free the ECDH operation arguments
 * @args: SMW's Key derivation arguments
 */
static void kdf_ecdh_free(struct smw_derive_key_args *args)
{
	struct smw_kdf_ecdh_args *ecdh_args = NULL;

	if (args) {
		if (args->kdf_arguments) {
			ecdh_args = args->kdf_arguments;

			free(ecdh_args);

			args->kdf_arguments = NULL;
		}
	}
}

static const struct kdf_op {
	smw_kdf_t name;
	int (*setup_base)(struct subtest_data *subtest,
			  struct smw_derive_key_args *args,
			  struct keypair_ops *key_base,
			  struct smw_keypair_buffer *base_buffer);
	int (*read_args)(void **kdf_args, struct subtest_data *subtest,
			 struct json_object *oargs);
	int (*prepare_result)(struct subtest_data *subtest,
			      struct smw_derive_key_args *args);
	int (*end_operation)(struct subtest_data *subtest,
			     struct smw_derive_key_args *args);
	void (*free)(struct smw_derive_key_args *args);
} kdf_ops[] = { {
			.name = SMW_KDF_NAME_TLS12_KEY_EXCHANGE,
			.setup_base = &kdf_tls12_setup_base_key,
			.read_args = &kdf_tls12_read_args,
			.prepare_result = &kdf_tls12_prepare_result,
			.end_operation = &kdf_tls12_end_operation,
			.free = &kdf_tls12_free,
		},
		{
			.name = SMW_KDF_NAME_HKDF,
			.setup_base = &kdf_hkdf_setup_base_key,
			.read_args = &kdf_hkdf_read_args,
			.prepare_result = &kdf_hkdf_prepare_result,
			.end_operation = &kdf_hkdf_end_operation,
			.free = &kdf_hkdf_free,
		},
		{
			.name = SMW_KDF_NAME_ECDH,
			.setup_base = &kdf_ecdh_setup_base_key,
			.read_args = &kdf_ecdh_read_args,
			.prepare_result = &kdf_ecdh_prepare_result,
			.end_operation = &kdf_ecdh_end_operation,
			.free = &kdf_ecdh_free,
		},
		{
			.name = SMW_KDF_NAME_TLS12_OP_KEY_EXCHANGE,
			.setup_base = &kdf_tls12_setup_base_key,
			.read_args = &kdf_tls12_op_read_args,
			.prepare_result = &kdf_tls12_prepare_result,
			.end_operation = &kdf_tls12_op_end_operation,
			.free = &kdf_tls12_op_free,
		},
		{ 0 } };

/**
 * get_kdf_op() - Find the Key Derivation name in the KDF operation
 * @kdf_name: Key Derivation Function name
 *
 * Return:
 * Pointer to the entry in the KDF operation list if found,
 * otherwise NULL
 */
static const struct kdf_op *get_kdf_op(smw_kdf_t kdf_name)
{
	unsigned int i = 0;
	const struct kdf_op *entry = NULL;

	for (; i < ARRAY_SIZE(kdf_ops); i++) {
		entry = &kdf_ops[i];
		if (kdf_name != SMW_KDF_NAME_NONE && entry->name == kdf_name)
			return entry;
	}

	return NULL;
}

/**
 * kdf_setup_base() - Setup the key derivation base key arguments.
 * @subtest: Subtest data.
 * @args: Pointer to public key derivation argument structure.
 * @key_base: Test keypair operations.
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
static int kdf_setup_base(struct subtest_data *subtest,
			  struct smw_derive_key_args *args,
			  struct keypair_ops *key_base,
			  struct smw_keypair_buffer *base_buffer)
{
	int res = ERR_CODE(FAILED);

	const struct kdf_op *kdf_op;

	kdf_op = get_kdf_op(args->kdf_name);
	if (kdf_op && kdf_op->setup_base)
		res = kdf_op->setup_base(subtest, args, key_base, base_buffer);

	return res;
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
			 struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);

	const struct kdf_op *kdf_op = NULL;
	struct json_object *oargs = NULL;
	const char *op_type_string = NULL;

	/* Get the key derivation function if any */
	res = util_read_json_type(&op_type_string, OP_TYPE_OBJ, t_string,
				  subtest->params);

	if (res == ERR_CODE(VALUE_NOTFOUND)) {
		args->kdf_name = SMW_KDF_NAME_NONE;
		args->kdf_arguments = NULL;
		return ERR_CODE(PASSED);
	}

	if (res != ERR_CODE(PASSED))
		return res;

	args->kdf_name = get_kdf_name(op_type_string);

	kdf_op = get_kdf_op(args->kdf_name);

	if (!kdf_op) {
		args->kdf_arguments = NULL;
	} else if (kdf_op->read_args) {
		res = util_read_json_type(&oargs, OP_ARGS_OBJ, t_object,
					  subtest->params);
		if (res == ERR_CODE(PASSED) && oargs)
			res = kdf_op->read_args(&args->kdf_arguments, subtest,
						oargs);
	}

	return res;
}

/**
 * setup_derive_opt_params() - Setup key derive optional parameters.
 * @subtest: Subtest data
 * @args: Pointer to SMW's derive key arguments structure
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
	int res = ERR_CODE(BAD_ARGS);

	if (!subtest || !args || !args->key_attributes) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&args->store_derived_key, STORE_KEY_OBJ,
				  t_boolean, subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	/* Read (if any) the key derivation function name and arguments */
	res = kdf_args_read(args, subtest);

	return res;
}

/**
 * setup_derive_output() - Setup the key derivation output arguments.
 * @subtest: Subtest data
 * @args: Pointer to SMW's derive key arguments
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -FAILED                  - Error in definition file
 */
static int setup_derive_output(struct subtest_data *subtest,
			       struct smw_derive_key_args *args)
{
	int res = ERR_CODE(PASSED);

	const struct kdf_op *kdf_op = NULL;

	kdf_op = get_kdf_op(args->kdf_name);

	if (kdf_op && kdf_op->prepare_result)
		res = kdf_op->prepare_result(subtest, args);

	return res;
}

/**
 * end_derive_operation() - End key derivation operations.
 * @subtest: Subtest data
 * @args: Pointer to SMW's derive key arguments
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
				struct smw_derive_key_args *args)
{
	int res = ERR_CODE(FAILED);

	const struct kdf_op *kdf_op = NULL;

	kdf_op = get_kdf_op(args->kdf_name);

	if (kdf_op && kdf_op->end_operation)
		res = kdf_op->end_operation(subtest, args);

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
	int ret = ERR_CODE(BAD_ARGS);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!params || !args)
		return ret;

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case CTX_NULL:
		break;

	case KEY_DESC_NULL:
		(*args)->key_descriptor_base = NULL;
		break;

	case KEY_DESC_OUT_NULL:
		(*args)->key_descriptor_derived = NULL;
		break;

	case KDF_ARGS_NULL:
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
	struct smw_derived_key_descriptor key_derived = { 0 };
	struct smw_keypair_buffer base_buffer = { 0 };
	struct smw_derive_key_args args = { 0 };
	struct smw_key_attributes key_attributes = { 0 };
	struct smw_derive_key_args *smw_args = &args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.subsystem_name = subtest->subsystem;
	args.key_attributes = &key_attributes;
	args.key_descriptor_base = &key_base.desc;
	args.key_descriptor_derived = &key_derived;

	/* Setup optional parameters */
	res = setup_derive_opt_params(subtest, &args);
	if (res != ERR_CODE(PASSED) && !is_api_test(subtest))
		goto exit;

	res = kdf_setup_base(subtest, &args, &key_base, &base_buffer);
	if (res != ERR_CODE(PASSED) && !is_api_test(subtest))
		goto exit;

	/* Setup the output arguments */
	res = setup_derive_output(subtest, &args);
	if (res != ERR_CODE(PASSED) && !is_api_test(subtest))
		goto exit;

	res = derive_bad_params(subtest->params, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	subtest->smw_status = smw_derive_key(smw_args);
	if (subtest->smw_status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
		subtest->smw_status = SMW_STATUS_OK;

	if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
		DBG_PRINT("Shared secret buffer too short, expected length = %u",
			  args.key_descriptor_derived->shared_secret_len);

	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);
	else
		res = end_derive_operation(subtest, &args);

exit:
	key_free_key(&key_base);

	/*
	 * Don't free key data if it's present in key linked list
	 * (ephemeral keys)
	 */
	if (args.key_descriptor_derived && args.key_descriptor_derived->id)
		free(args.key_descriptor_derived->shared_secret);

	kdf_args_free(&args);

	return res;
}
