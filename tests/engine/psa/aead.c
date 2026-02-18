// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024, 2026 NXP
 */

#include <string.h>

#include <json.h>

#include <psa/crypto.h>

#include "aead.h"
#include "types.h"
#include "util.h"
#include "util_aead.h"
#include "key.h"

#define MAX_IV_LEN 64

#define AEAD_ALGO(_id)                                                         \
	{                                                                      \
		.name = #_id, .psa_alg_id = PSA_ALG_##_id                      \
	}

/**
 * struct aead_alg_info
 * @name: AEAD algo name.
 * @psa_alg_id: PSA AEAD algo id.
 */
static struct aead_alg_info {
	const char *name;
	psa_algorithm_t psa_alg_id;
} aead_alg_info[] = { AEAD_ALGO(CCM),
		      AEAD_ALGO(GCM),
		      AEAD_ALGO(CHACHA20_POLY1305),
		      { .name = NULL, .psa_alg_id = PSA_ALG_NONE } };

static struct aead_alg_info *get_aead_alg_info(const char *alg_name)
{
	return GET_INFO(alg_name, aead_alg_info);
}

/**
 * set_output_params() - Set AEAD output related parameters
 * @subtest: Subtest data
 * @input_length: Input length
 * @encrypt_op: True if operation is encryption
 * @exp_output: A buffer in which to store the expected output data
 * @output: A buffer to store the operation output buffer
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int set_output_params(struct subtest_data *subtest,
			     unsigned int input_length, bool encrypt_op,
			     struct tbuffer *exp_output, struct tbuffer *output)
{
	int res = ERR_CODE(PASSED);

	if (input_length >= UINT_MAX - PSA_AEAD_TAG_MAX_SIZE) {
		DBG_PRINT("Input length too large");
		return ERR_CODE(BAD_ARGS);
	}

	/* Read expected output buffer */
	res = util_read_json_type(exp_output, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read output buffer");
		return res;
	}

	/* Output length is not set by definition file */
	if (res == ERR_CODE(VALUE_NOTFOUND) || !exp_output->length) {
		/* Set a value large enough */
		output->length =
			encrypt_op ?
				PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(input_length) :
				PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(input_length);
	} else {
		output->length = exp_output->length;
	}

	/* If length is set to 0 by definition file output pointer is NULL */
	if (output->length) {
		output->data = calloc(1, output->length);
		if (!output->data)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		/*
		 * Specific error case where output pointer is set and output
		 * length not
		 */
		if (!exp_output->length && exp_output->data)
			output->length = 0;
	}

	return ERR_CODE(PASSED);
}

static int check_tag_follows_output(struct tbuffer input, struct tbuffer output,
				    size_t tag_length)
{
	static const unsigned char zeros[8] = { 0 };

	if (!output.data)
		return ERR_CODE(PASSED);

	if (tag_length > sizeof(zeros))
		tag_length = sizeof(zeros);

	if (!memcmp(output.data + input.length, zeros, tag_length))
		return ERR_CODE(FAILED);

	return ERR_CODE(PASSED);
}

typedef psa_status_t (*psa_aead_function)(psa_key_id_t, psa_algorithm_t,
					  const uint8_t *, size_t,
					  const uint8_t *, size_t,
					  const uint8_t *, size_t, uint8_t *,
					  size_t, size_t *);

int aead_operation_psa(struct subtest_data *subtest,
		       psa_aead_function psa_aead_func)
{
	int res = ERR_CODE(BAD_ARGS);
	const char *key_name = NULL;
	char *mode_name = NULL;
	struct keypair_psa key_test = { 0 };
	psa_key_id_t key = PSA_KEY_ID_NULL;
	struct aead_alg_info *aead_alg_info = NULL;

	struct tbuffer input = { 0 };
	struct tbuffer iv = { 0 };
	struct tbuffer aad = { 0 };

	struct tbuffer output = { 0 };
	size_t ciphertext_length = 0;
	struct tbuffer exp_output = { 0 };

	unsigned int tag_length = 0;
	psa_algorithm_t alg = PSA_ALG_NONE;
	int aead_id = INT_MAX;

	bool encrypt_op = (psa_aead_func == &psa_aead_encrypt);

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	key = key_test.attributes.id;
	if (key_test.data)
		free(key_test.data);

	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_int,
				  subtest->params);
	if (res == ERR_CODE(PASSED) && aead_id != INT_MAX)
		res = util_aead_find_node(list_aead_output(subtest), aead_id,
					  &input.data, &input.length, NULL,
					  &tag_length, &iv.data, &iv.length, 0);

	if (!iv.data) {
		res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex,
					  subtest->params);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	if (!input.data) {
		res = util_read_json_type(&input, INPUT_OBJ, t_buffer_hex,
					  subtest->params);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	if (tag_length == 0) {
		res = util_read_json_type(&tag_length, TAG_OBJ, t_uint,
					  subtest->params);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;
	}

	res = util_read_json_type(&mode_name, MODE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto end;

	aead_alg_info = get_aead_alg_info(mode_name);
	if (!aead_alg_info) {
		res = ERR_CODE(BAD_ARGS);
		goto end;
	}

	res = util_read_json_type(&aad, AAD_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = set_output_params(subtest, input.length, encrypt_op, &exp_output,
				&output);
	if (res != ERR_CODE(PASSED))
		goto end;

	alg = (tag_length == 0) ?
		      aead_alg_info->psa_alg_id :
		      PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg_info->psa_alg_id,
						      tag_length);

	subtest->psa_status =
		psa_aead_func(key, alg, iv.data, iv.length, aad.data,
			      aad.length, input.data, input.length, output.data,
			      output.length, &ciphertext_length);

	if (exp_output.data && exp_output.length) {
		res = util_compare_buffers(output.data, ciphertext_length,
					   exp_output.data, exp_output.length);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	if (!encrypt_op)
		goto end;

	/* tag_length can still be 0 here, meaning the "default" for the specified
	 * algorithm. Update it according to the output length.
	 */
	SET_OVERFLOW(ciphertext_length - input.length, tag_length);

	if (aead_id != INT_MAX && ciphertext_length < UINT_MAX) {
		util_aead_add_output_data(list_aead_output(subtest), aead_id,
					  output.data,
					  (unsigned int)ciphertext_length, NULL,
					  tag_length, iv.data, iv.length);
	}

	if (subtest->psa_status == PSA_SUCCESS)
		res = check_tag_follows_output(input, output, tag_length);

end:
	if (encrypt_op || aead_id == INT_MAX) {
		if (iv.data)
			free(iv.data);

		if (input.data)
			free(input.data);
	}

	if (output.data)
		free(output.data);

	if (aad.data)
		free(aad.data);

	if (exp_output.data)
		free(exp_output.data);

	return res;
}

int aead_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	char *op_type = NULL;

	res = util_read_json_type(&op_type, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD op_type");
		return ERR_CODE(MISSING_PARAMS);
	}

	if (!strcmp(op_type, OP_TYPE_ENCRYPT_STR))
		return aead_operation_psa(subtest, psa_aead_encrypt);
	else if (!strcmp(op_type, OP_TYPE_DECRYPT_STR))
		return aead_operation_psa(subtest, psa_aead_decrypt);

	DBG_PRINT_BAD_PARAM("AEAD op_type");
	return ERR_CODE(BAD_ARGS);
}
