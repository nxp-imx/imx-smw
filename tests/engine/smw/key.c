// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <smw/names.h>

#include "types.h"
#include "util.h"
#include "util_attr.h"
#include "util_key.h"

#include "key.h"

#define KEY_TYPE(_name)                                                        \
	{                                                                      \
		.name = SMW_KEY_TYPE_NAME_##_name, .string = #_name            \
	}

static struct {
	smw_key_type_t name;
	const char *string;
} key_type_names[] = {
	KEY_TYPE(SECP_R1),    KEY_TYPE(BRAINPOOL_R1), KEY_TYPE(BRAINPOOL_T1),
	KEY_TYPE(ED25519),    KEY_TYPE(AES),	      KEY_TYPE(DES),
	KEY_TYPE(DES3),	      KEY_TYPE(DSA_SM2_FP),   KEY_TYPE(SM4),
	KEY_TYPE(HMAC),	      KEY_TYPE(RSA),	      KEY_TYPE(DH),
	KEY_TYPE(TLS_MASTER), KEY_TYPE(RAW),	      KEY_TYPE(DERIVE),
	KEY_TYPE(HKDF_IKM),
};

#define KEY_FORMAT(_name)                                                      \
	{                                                                      \
		.name = SMW_KEY_FORMAT_NAME_##_name, .string = #_name          \
	}

static struct {
	smw_key_format_t name;
	const char *string;
} key_format_names[] = { KEY_FORMAT(HEX), KEY_FORMAT(BASE64) };

static const struct util_attr_info algo_info[] = {
	ATTR_ALGO(ECB_NO_PADDING, SYMMETRIC_ENCRYPTION, DEFAULT, ECB_NO_PAD,
		  NONE),
	ATTR_ALGO(CFB, SYMMETRIC_ENCRYPTION, DEFAULT, CFB, NONE),
	ATTR_ALGO(CTR, SYMMETRIC_ENCRYPTION, DEFAULT, CTR, NONE),
	ATTR_ALGO(OFB, SYMMETRIC_ENCRYPTION, DEFAULT, OFB, NONE),
	ATTR_ALGO(XTS, SYMMETRIC_ENCRYPTION, DEFAULT, XTS, NONE),
	ATTR_ALGO(CCM, AEAD, DEFAULT, CCM, ANY),
	ATTR_ALGO(GCM, AEAD, DEFAULT, GCM, ANY),
	ATTR_ALGO(CHACHA20_POLY1305, AEAD, DEFAULT, POLY1305, ANY),
	ATTR_ALGO(CMAC, MAC, DEFAULT, CMAC, NONE),
	ATTR_ALGO(HMAC, MAC, HMAC, NONE, ANY),
	ATTR_ALGO(DEFAULT, ASYMMETRIC_SIGNATURE, DEFAULT, ANY, ANY),
	ATTR_ALGO_CURVE(ECDSA, ASYMMETRIC_SIGNATURE, ECDSA, ANY, ANY),
	ATTR_ALGO_CURVE(EDDSA, ASYMMETRIC_SIGNATURE, EDDSA, ED25519, ANY),
	ATTR_ALGO(DSA, ASYMMETRIC_SIGNATURE, DSA, ANY, ANY),
	ATTR_ALGO(RSA, ASYMMETRIC_SIGNATURE, RSA, ANY, ANY),
	ATTR_ALGO(RSA_PKCS1V15, ASYMMETRIC_SIGNATURE, RSA, PKCS1_1_5, ANY),
	ATTR_ALGO(RSA_PSS, ASYMMETRIC_SIGNATURE, RSA, PSS, ANY),
	ATTR_ALGO(TLS_1_2, KEY_DERIVATION, TLS_1_2, NONE, ANY),
	ATTR_ALGO(TLS_1_2_CLIENT, ASYMMETRIC_SIGNATURE, TLS_1_2, CLIENT, ANY),
	ATTR_ALGO(TLS_1_2_SERVER, ASYMMETRIC_SIGNATURE, TLS_1_2, SERVER, ANY),
	ATTR_ALGO(ATTEST_CMAC, KEY_ATTESTATION, DEFAULT, CMAC, ANY),
	ATTR_ALGO_CURVE(ATTEST_ECDSA, KEY_ATTESTATION, ECDSA, ANY, ANY),
	ATTR_ALGO(HKDF, KEY_DERIVATION, HKDF, NONE, ANY),
	ATTR_ALGO(HKDF_EXTRACT, KEY_DERIVATION, HKDF_EXTRACT, NONE, ANY),
	ATTR_ALGO(HKDF_EXPAND, KEY_DERIVATION, HKDF_EXPAND, NONE, ANY),
	{ .string = NULL }
};

static const struct util_attr_info hash_info[] = {
	ATTR_HASH(NONE),     ATTR_HASH(MD5),	  ATTR_HASH(SHA1),
	ATTR_HASH(SHA224),   ATTR_HASH(SHA256),	  ATTR_HASH(SHA384),
	ATTR_HASH(SHA512),   ATTR_HASH(SM3),	  ATTR_HASH(SHA3_224),
	ATTR_HASH(SHA3_256), ATTR_HASH(SHA3_384), ATTR_HASH(SHA3_512),
	{ .string = NULL }
};

static const struct util_attr_info usage_info[] = {
	ATTR_USAGE(CACHE),	 ATTR_USAGE(COPY),
	ATTR_USAGE(EXPORT),	 ATTR_USAGE(DERIVE),
	ATTR_USAGE(ENCRYPT),	 ATTR_USAGE(DECRYPT),
	ATTR_USAGE(SIGN_HASH),	 ATTR_USAGE(SIGN_MESSAGE),
	ATTR_USAGE(VERIFY_HASH), ATTR_USAGE(VERIFY_MESSAGE),
	{ .string = NULL }
};

static const struct util_attr_info attributes_info[] = {
	ATTR_PERSISTENCE(TRANSIENT),
	ATTR_PERSISTENCE(PERSISTENT),
	ATTR_PERSISTENCE(PERMANENT),
	{ .string = NULL }
};

static struct smw_keypair_gen *get_keypair_gen(struct keypair_ops *this)
{
	assert(this && this->keys);
	return &this->keys->gen;
}

static unsigned char **get_public_data_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->public_data;
}

static unsigned int *get_public_length_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->public_length;
}

static unsigned char **get_private_data_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->private_data;
}

static unsigned int *get_private_length_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->private_length;
}

static struct smw_keypair_rsa *get_keypair_rsa(struct keypair_ops *this)
{
	assert(this && this->keys);
	return &this->keys->rsa;
}

static unsigned char **get_public_data_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->public_data;
}

static unsigned int *get_public_length_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->public_length;
}

static unsigned char **get_private_data_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->private_data;
}

static unsigned int *get_private_length_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->private_length;
}

static unsigned char **get_modulus_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->modulus;
}

static unsigned int *get_modulus_length_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->modulus_length;
}

static unsigned char **get_public_exponent_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->public_exponent;
}

static unsigned int *get_public_exponent_length_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->public_exponent_length;
}

void set_key_ops(struct keypair_ops *key_test)
{
	if (!key_test->keys) {
		key_test->public_data = NULL;
		key_test->public_length = NULL;
		key_test->private_data = NULL;
		key_test->private_length = NULL;
		key_test->modulus = NULL;
		key_test->modulus_length = NULL;
		key_test->public_exponent = NULL;
		key_test->public_exponent_length = NULL;

		return;
	}

	if (key_test->desc.type_name == SMW_KEY_TYPE_NAME_RSA) {
		key_test->public_data = &get_public_data_rsa;
		key_test->public_length = &get_public_length_rsa;
		key_test->private_data = &get_private_data_rsa;
		key_test->private_length = &get_private_length_rsa;
		key_test->modulus = &get_modulus_rsa;
		key_test->modulus_length = &get_modulus_length_rsa;
		key_test->public_exponent = &get_public_exponent_rsa;
		key_test->public_exponent_length =
			&get_public_exponent_length_rsa;

		*key_modulus(key_test) = NULL;
		*key_modulus_length(key_test) = KEY_LENGTH_NOT_SET;
	} else {
		key_test->public_data = &get_public_data_gen;
		key_test->public_length = &get_public_length_gen;
		key_test->private_data = &get_private_data_gen;
		key_test->private_length = &get_private_length_gen;
		key_test->modulus = NULL;
		key_test->modulus_length = NULL;
		key_test->public_exponent = NULL;
		key_test->public_exponent_length = NULL;
	}

	key_test->keys->format_name = SMW_KEY_FORMAT_NAME_NONE;
	*key_public_data(key_test) = NULL;
	*key_public_length(key_test) = KEY_LENGTH_NOT_SET;
	*key_private_data(key_test) = NULL;
	*key_private_length(key_test) = KEY_LENGTH_NOT_SET;
}

/**
 * keypair_read() - Read the public and private key definition
 * @key_test: Test keypair structure with operations
 * @params: json-c object
 *
 * Read and set the key format, public key buffer and private key buffer.
 * Key buffer is defined by a string.
 * The public and private data buffer of the @key SMW buffer object are
 * allocated by this function but must be freed by caller if function
 * succeed.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
static int keypair_read(struct keypair_ops *key_test,
			struct json_object *params)
{
	int ret = ERR_CODE(PASSED);
	const char *format_string = NULL;

	if (!params || !key_test || !key_test->keys) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_read_json_type(&format_string, FORMAT_OBJ, t_string, params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	key_test->keys->format_name = key_get_format_name(format_string);

	ret = util_read_obj_value(key_public_data(key_test),
				  key_public_length(key_test), PUB_KEY_OBJ,
				  params);

	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_read_obj_value(key_private_data(key_test),
				  key_private_length(key_test), PRIV_KEY_OBJ,
				  params);

	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (key_test->desc.type_name == SMW_KEY_TYPE_NAME_RSA) {
		ret = util_read_obj_value(key_modulus(key_test),
					  key_modulus_length(key_test),
					  MODULUS_OBJ, params);
		if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
			return ret;

		ret = util_read_obj_value(key_public_exponent(key_test),
					  key_public_exponent_length(key_test),
					  PUB_EXP_OBJ, params);
	}

	if (ret == ERR_CODE(VALUE_NOTFOUND))
		ret = ERR_CODE(PASSED);

	return ret;
}

static void key_free_key_buffers(struct keypair_ops *key_test)
{
	if (key_test && key_test->keys) {
		if (*key_public_data(key_test))
			free(*key_public_data(key_test));

		if (*key_private_data(key_test))
			free(*key_private_data(key_test));

		if (key_test->modulus && *key_modulus(key_test))
			free(*key_modulus(key_test));
	}
}

smw_key_type_t key_get_type_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_KEY_TYPE_NAME_NONE;

	for (; i < ARRAY_SIZE(key_type_names); i++) {
		if (!strcmp(key_type_names[i].string, string))
			return key_type_names[i].name;
	}

	return SMW_KEY_TYPE_NAME_NB + 1;
}

smw_key_format_t key_get_format_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_KEY_FORMAT_NAME_NONE;

	for (; i < ARRAY_SIZE(key_format_names); i++) {
		if (!strcmp(key_format_names[i].string, string))
			return key_format_names[i].name;
	}

	return SMW_KEY_FORMAT_NAME_NB + 1;
}

static int read_descriptor(struct llist *keys, struct keypair_ops *key_test,
			   const char *key_name, struct llist *key_names)
{
	int ret = ERR_CODE(PASSED);
	struct key_data *data = NULL;
	const char *parent_key_name = NULL;
	struct smw_key_descriptor *desc = NULL;
	const char *type_string = NULL;
	void *dummy = NULL;

	if (!key_test || !key_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	desc = &key_test->desc;

	ret = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	if (data->identifier) {
		desc->id = data->identifier;
		desc->security_size = 0;

		(void)smw_get_key_type_name(desc);
		(void)smw_get_security_size(desc);

		set_key_ops(key_test);

		return ERR_CODE(PASSED);
	}

	if (!data->okey_params)
		return ERR_CODE(PASSED);

	ret = util_read_json_type(&parent_key_name, KEY_NAME_OBJ, t_string,
				  data->okey_params);

	if (ret == ERR_CODE(PASSED) && parent_key_name) {
		ret = util_list_find_node(key_names, (uintptr_t)parent_key_name,
					  &dummy);
		if (ret != ERR_CODE(PASSED))
			return ret;

		if (dummy) {
			DBG_PRINT("Error: nested key definition (%s, %s)",
				  parent_key_name, key_name);
			return ERR_CODE(BAD_ARGS);
		}

		/*
		 * Add a node in list key_names with id set to parent_key_name.
		 * No data is stored by the node. But data pointer must be different to NULL
		 * in order to detect later if the node is found in the list.
		 * Data pointer is not freed when the list is cleared
		 * because the method to free the data is set to NULL
		 * when list is initialized.
		 */
		ret = util_list_add_node(key_names, (uintptr_t)parent_key_name,
					 (void *)1);
		if (ret != ERR_CODE(PASSED))
			return ret;

		ret = read_descriptor(keys, key_test, parent_key_name,
				      key_names);
		if (ret != ERR_CODE(PASSED))
			return ret;
	} else if (ret != ERR_CODE(VALUE_NOTFOUND)) {
		return ret;
	}

	/* Read 'type' parameter if defined */
	ret = util_read_json_type(&type_string, TYPE_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (ret == ERR_CODE(PASSED)) {
		if (desc->type_name != SMW_KEY_TYPE_NAME_NONE)
			key_free_key_buffers(key_test);

		desc->type_name = key_get_type_name(type_string);
	}

	/* Read 'security_size' parameter if defined */
	ret = util_read_json_type(&desc->security_size, SEC_SIZE_OBJ, t_int,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'id' parameter if defined */
	ret = util_read_json_type(&desc->id, ID_OBJ, t_uint, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Setup the key ops function of the key type */
	set_key_ops(key_test);

	if (key_test->keys) {
		ret = keypair_read(key_test, data->okey_params);
		if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
			return ret;
	}

	return ERR_CODE(PASSED);
}

int key_desc_init(struct keypair_ops *key_test, struct smw_keypair_buffer *key)
{
	struct smw_key_descriptor *desc = NULL;

	if (!key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	desc = &key_test->desc;

	desc->type_name = SMW_KEY_TYPE_NAME_NONE;
	desc->security_size = KEY_SECURITY_NOT_SET;
	desc->id = KEY_ID_NOT_SET;
	desc->buffer = key;

	key_test->keys = key;

	/* Initialize the keypair buffer and operations */
	set_key_ops(key_test);

	return ERR_CODE(PASSED);
}

int key_read_descriptor(struct llist *keys, struct keypair_ops *key_test,
			const char *key_name)
{
	int res = ERR_CODE(PASSED);
	int err = ERR_CODE(PASSED);

	struct llist *key_names = NULL;

	res = util_list_init(&key_names, NULL, LIST_ID_TYPE_STRING);

	if (res == ERR_CODE(PASSED))
		res = read_descriptor(keys, key_test, key_name, key_names);

	err = util_list_clear(key_names);
	if (res == ERR_CODE(PASSED))
		res = err;

	return res;
}

int key_desc_set_key(struct keypair_ops *key_test,
		     struct smw_keypair_buffer *key)
{
	if (!key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	key_test->desc.buffer = key;
	key_test->keys = key;

	/* Initialize the keypair buffer and operations */
	set_key_ops(key_test);

	return ERR_CODE(PASSED);
}

void key_free_key(struct keypair_ops *key_test)
{
	key_free_key_buffers(key_test);

	(void)key_desc_set_key(key_test, NULL);
}

void key_prepare_key_data(struct keypair_ops *key_test,
			  struct key_data *key_data)
{
	key_data->identifier = key_test->desc.id;
	if (key_test->keys) {
		key_data->pub_key.data = *key_test->public_data(key_test);
		key_data->pub_key.length = *key_test->public_length(key_test);
	}
}

/**
 * allocate_keys() - Allocate all fields present in keys structure
 * @keys: Pointer to structure to update
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failure
 */
static int allocate_keys(struct keys *keys)
{
	struct keypair_ops *keys_test = NULL;
	struct smw_key_descriptor **keys_desc = NULL;
	struct smw_keypair_buffer *keys_buffer = NULL;
	size_t alloc_size = 0;

	if (!keys->nb_keys)
		return ERR_CODE(INTERNAL);

	/* Allocate keypair ops array */
	if (MUL_OVERFLOW(keys->nb_keys, sizeof(*keys_test), &alloc_size))
		goto err;

	keys_test = calloc(1, alloc_size);
	if (!keys_test)
		goto err;

	/* Allocate keys descriptor array */
	if (MUL_OVERFLOW(keys->nb_keys, sizeof(*keys_desc), &alloc_size))
		goto err;

	keys_desc = calloc(1, alloc_size);
	if (!keys_desc)
		goto err;

	/* Allocate keys buffer array */
	if (MUL_OVERFLOW(keys->nb_keys, sizeof(*keys_buffer), &alloc_size))
		goto err;

	keys_buffer = calloc(1, alloc_size);
	if (!keys_buffer)
		goto err;

	keys->keys_test = keys_test;
	keys->keys_desc = keys_desc;
	keys->keys_buffer = keys_buffer;

	return ERR_CODE(PASSED);

err:
	if (keys_test)
		free(keys_test);

	if (keys_desc)
		free(keys_desc);

	return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
}

static void perm_algo_callback(void *user_data, const char *params[],
			       size_t n_params)
{
	smw_attr_algo_t *algo = user_data;

	algorithm_callback(user_data, params, n_params);

	if (SMW_ATTR_GET_CLASS(*algo) == SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE &&
	    SMW_ATTR_GET_ALGO(*algo) == SMW_ATTR_ALGO_ECDSA)
		*algo = SMW_ATTR_SET_CLEAR_NAME(*algo, CURVE, NONE);

	DBG_PRINT("SMW permitted algorithm: %0" PRIx64, *algo);
}

void free_keys(struct keys *keys)
{
	unsigned int i = 0;

	if (keys->keys_desc) {
		free(keys->keys_desc);
		keys->keys_desc = NULL;
	}

	for (; i < keys->nb_keys; i++)
		key_free_key(&keys->keys_test[i]);

	if (keys->keys_buffer) {
		free(keys->keys_buffer);
		keys->keys_buffer = NULL;
	}

	if (keys->keys_test) {
		free(keys->keys_test);
		keys->keys_test = NULL;
	}
}

int key_read_descriptors(struct subtest_data *subtest, const char *key,
			 unsigned int *nb_keys,
			 struct smw_key_descriptor ***keys_desc,
			 struct keys *keys)

{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int i = 0;
	struct keypair_ops *key_test = NULL;
	struct json_object *okey_name = NULL;
	struct json_object *obj = NULL;
	const char *key_name = NULL;

	res = util_read_json_type(&key_name, key, t_string, subtest->params);
	if (res == ERR_CODE(PASSED)) {
		*nb_keys = 1;
	} else if (res == ERR_CODE(BAD_PARAM_TYPE)) {
		res = util_read_json_type(&okey_name, key, t_array,
					  subtest->params);
		if (res != ERR_CODE(PASSED))
			return res;

		if (SET_OVERFLOW(json_object_array_length(okey_name), *nb_keys))
			return ERR_CODE(INTERNAL);
	} else {
		return res;
	}

	/*
	 * If this is API test number of keys = 0, need to allocate
	 * at least one key, else test is failed for other reason.
	 */
	keys->nb_keys = *nb_keys;
	if (is_api_test(subtest) && keys->nb_keys == 0)
		keys->nb_keys = 1;

	res = allocate_keys(keys);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!keys->keys_test || !keys->keys_desc || !keys->keys_buffer)
		return ERR_CODE(INTERNAL);

	for (i = 0; i < keys->nb_keys; i++) {
		key_test = &keys->keys_test[i];

		/* Initialize key descriptor */
		res = key_desc_init(key_test, &keys->keys_buffer[i]);
		if (res != ERR_CODE(PASSED))
			return res;

		if (okey_name) {
			obj = json_object_array_get_idx(okey_name, i);
			if (obj)
				key_name = json_object_get_string(obj);
		}

		if (key_name) {
			res = key_read_descriptor(list_keys(subtest), key_test,
						  key_name);

			if (res != ERR_CODE(PASSED))
				return res;

			if (key_is_id_set(key_test))
				key_free_key(key_test);
		}

		if (!key_is_id_set(key_test) && !is_api_test(subtest) &&
		    (!key_is_type_set(key_test) ||
		     !key_is_security_set(key_test) ||
		     !key_is_private_key_defined(key_test))) {
			DBG_PRINT_MISS_PARAM("Key description");
			return ERR_CODE(MISSING_PARAMS);
		}

		key_name = NULL;

		keys->keys_desc[i] = &key_test->desc;
	}

	*keys_desc = keys->keys_desc;

	return ERR_CODE(PASSED);
}

void algorithm_callback(void *user_data, const char *params[], size_t n_params)
{
	smw_attr_algo_t *algo = user_data;
	size_t i = 1;
	const char *param = NULL;
	smw_attr_algo_t hash = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t length = 0;

	*algo = ATTR_ARRAY_FIND_MATCH(algo_info, params[0]).smw_algo;

	for (; i < n_params; i++) {
		param = params[i];

		if (!strncmp(param, HASH_STR, strlen(HASH_STR))) {
			param += strlen(HASH_STR);

			hash = ATTR_ARRAY_FIND_MATCH(hash_info, param).smw_algo;

			*algo = SMW_ATTR_SET_HASH(*algo, hash);
		} else if (!strncmp(param, MIN_LENGTH_STR,
				    strlen(MIN_LENGTH_STR))) {
			param += strlen(MIN_LENGTH_STR);

			(void)SET_OVERFLOW(atol(param), length);

			*algo = SMW_ATTR_SET_MIN_LENGTH(*algo, length);
		} else if (!strncmp(param, LENGTH_STR, strlen(LENGTH_STR))) {
			param += strlen(LENGTH_STR);

			(void)SET_OVERFLOW(atol(param), length);

			*algo = SMW_ATTR_SET_LENGTH(*algo, length);
		}
	}

	DBG_PRINT("SMW algorithm: %0" PRIx64, *algo);
}

void usage_callback(void *user_data, const char *attributes[],
		    size_t n_attributes)
{
	smw_attr_usage_t *usage_flags = user_data;
	size_t i = 0;

	for (; i < n_attributes; i++)
		*usage_flags |= ATTR_ARRAY_FIND_MATCH(usage_info, attributes[i])
					.smw_usage;

	DBG_PRINT("SMW usage flags: %08x", *usage_flags);
}

void attributes_callback(void *user_data, const char *attributes[],
			 size_t n_attributes)
{
	smw_attr_attributes_t *attr = user_data;
	size_t i = 0;

	for (; i < n_attributes; i++)
		*attr |= ATTR_ARRAY_FIND_MATCH(attributes_info, attributes[i])
				 .smw_attributes;

	DBG_PRINT("SMW RW flags: %08x", *attributes);
}

int key_read_attributes(struct json_object *params,
			struct smw_key_attributes **attributes)
{
	int ret = ERR_CODE(PASSED);
	int found = 0;

	if (!params || !attributes || !*attributes) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_attr_read_attributes(params, USAGE_OBJ, &usage_callback,
					&((*attributes)->usage_flags));
	if (ret == ERR_CODE(PASSED))
		found++;
	else if (ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_attr_read_attributes(params, PERMITTED_ALGO_OBJ,
					&perm_algo_callback,
					&((*attributes)->permitted_algo));
	if (ret == ERR_CODE(PASSED))
		found++;
	else if (ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_attr_read_attributes(params, ATTR_LIST_OBJ,
					&attributes_callback,
					&((*attributes)->attributes));
	if (ret == ERR_CODE(PASSED))
		found++;
	else if (ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (!found)
		*attributes = NULL;

	return ERR_CODE(PASSED);
}
