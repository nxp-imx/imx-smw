// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024, 2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <psa/crypto.h>

#include "aead.h"
#include "types.h"
#include "util.h"
#include "util_aead.h"
#include "util_context.h"
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
 * aead_abort_op - Abort the AEAD operation if error
 * @error: Error condition to abort (!= ERR_CODE(PASSED))
 * @subtest: Subtest data
 * @operation: AEAD operation context
 *
 * Function aborts the AEAD operation if the @error is not PASSED and if
 * test definition doesn't set the "op_no_abort" parameter to true.
 *
 * Return:
 * PASSED      - Success
 * Other error
 */
static int aead_abort_op(int error, struct subtest_data *subtest,
			 psa_aead_operation_t *operation)
{
	int res = ERR_CODE(PASSED);
	bool op_no_abort = false;

	if (error == ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&op_no_abort, OP_NO_ABORT, t_boolean,
				  subtest->params);

	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		return res;

	if (!op_no_abort)
		(void)psa_aead_abort(operation);

	return ERR_CODE(PASSED);
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

static int is_aead_encrypt(struct subtest_data *subtest, bool *encrypt)
{
	int res = ERR_CODE(PASSED);
	const char *op_type_str = NULL;

	res = util_read_json_type(&op_type_str, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		DBG_PRINT_MISS_PARAM("AEAD op_type");
	else
		*encrypt = !strcmp(op_type_str, OP_TYPE_ENCRYPT_STR);

	return res;
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

	unsigned char *input_data = NULL;
	struct tbuffer input = { 0 };
	struct tbuffer iv = { 0 };
	struct tbuffer aad = { 0 };
	struct tbuffer tag = { 0 };

	struct tbuffer output = { 0 };
	size_t ciphertext_length = 0;
	struct tbuffer exp_output = { 0 };

	psa_algorithm_t alg = PSA_ALG_NONE;
	int aead_id = INT_MAX;
	bool tag_field_set = false;

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

	/* Read 'tag_field_set' parameter, if any */
	res = util_read_json_type(&tag_field_set, TAG_FIELD_SET_OBJ, t_boolean,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_int,
				  subtest->params);
	if (res == ERR_CODE(PASSED) && aead_id != INT_MAX) {
		/*
		 * If AEAD ID is defined, may be input, iv or tag are
		 * stored from a previous execution.
		 */
		res = util_aead_find_node(list_aead_output(subtest), aead_id,
					  &input_data, &input.length, &tag.data,
					  &tag.length, &iv.data, &iv.length,
					  tag_field_set);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;
	}

	if (!iv.data) {
		res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex,
					  subtest->params);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	input.data = input_data;
	if (!input.data) {
		res = util_read_json_type(&input, INPUT_OBJ, t_buffer_hex,
					  subtest->params);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	if (tag_field_set && !encrypt_op && tag.data) {
		/* Realloc input data to contantenate the tag */
		input.data = malloc(input.length + tag.length);
		if (!input.data) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}

		memcpy(input.data, input_data, input.length);
		memcpy(input.data + input.length, tag.data, tag.length);

		input.length += tag.length;
	}

	if (!tag.length) {
		res = util_read_json_type(&tag.length, TAG_OBJ, t_uint,
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

	alg = (tag.length == 0) ?
		      aead_alg_info->psa_alg_id :
		      PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg_info->psa_alg_id,
						      tag.length);

	subtest->psa_status =
		psa_aead_func(key, alg, iv.data, iv.length, aad.data,
			      aad.length, input.data, input.length, output.data,
			      output.length, &ciphertext_length);

	res = util_compare_buffers(output.data, ciphertext_length,
				   exp_output.data, exp_output.length);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (!encrypt_op)
		goto end;

	/* tag.length can still be 0 here, meaning the "default" for the specified
	 * algorithm. Update it according to the output length.
	 */
	SET_OVERFLOW(ciphertext_length - input.length, tag.length);

	if (aead_id != INT_MAX && ciphertext_length < UINT_MAX) {
		if (tag.length)
			tag.data = output.data + ciphertext_length - tag.length;

		util_aead_add_data(list_aead_output(subtest), aead_id,
				   output.data, (unsigned int)ciphertext_length,
				   tag.data, tag.length, iv.data, iv.length);
	}

	if (subtest->psa_status == PSA_SUCCESS)
		res = util_aead_check_tag_follows_output(output.data,
							 input.length,
							 tag.length);

end:
	if (encrypt_op || aead_id == INT_MAX) {
		if (iv.data)
			free(iv.data);
	}

	if (output.data)
		free(output.data);

	if (aad.data)
		free(aad.data);

	if (exp_output.data)
		free(exp_output.data);

	if (input.data && input_data != input.data)
		free(input.data);

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

int aead_init_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	int aead_id = INT_MAX;
	const char *key_name = NULL;
	const char *mode_name = NULL;
	struct keypair_psa key_test = { 0 };
	psa_key_id_t key = PSA_KEY_ID_NULL;
	struct aead_alg_info *alg_info = NULL;
	psa_algorithm_t alg = PSA_ALG_NONE;
	unsigned int tag_length = 0;
	unsigned int plaintext_length = 0;
	struct tbuffer aad = { 0 };
	struct tbuffer iv = { 0 };
	size_t iv_length = 0;
	struct smw_op_context *context = NULL;
	psa_aead_operation_t operation = psa_aead_operation_init();
	bool encrypt_op = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read aead_id for saving multipart encryption output */
	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	operation.op_context = context;

	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	key = key_test.attributes.id;
	if (key_test.data)
		free(key_test.data);

	res = util_read_json_type(&mode_name, MODE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD mode");
		goto exit;
	}

	alg_info = get_aead_alg_info(mode_name);
	if (!alg_info) {
		res = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	res = is_aead_encrypt(subtest, &encrypt_op);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_read_json_type(&tag_length, TAG_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	alg = (tag_length == 0) ?
		      alg_info->psa_alg_id :
		      PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg_info->psa_alg_id,
						      tag_length);

	if (encrypt_op)
		subtest->psa_status =
			psa_aead_encrypt_setup(&operation, key, alg);
	else
		subtest->psa_status =
			psa_aead_decrypt_setup(&operation, key, alg);

	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	/* Get plaintext length, if any */
	res = util_read_json_type(&plaintext_length, PLAINTEXT_LEN_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD plaintext length");
		goto exit;
	}

	res = util_read_json_type(&aad, AAD_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AAD");
		goto exit;
	}

	/*
	 * If plaintext length or aad length specified, set the AEAD
	 * message, aad lengths.
	 * Else can be set by the AEAD_SET_LENGTHS command in the test
	 * description. Knowning the aead set lengths must be called before
	 * the nonce/iv set or generate to not be in fault.
	 */
	if (plaintext_length || aad.length) {
		subtest->psa_status =
			psa_aead_set_lengths(&operation, aad.length,
					     plaintext_length);
		if (subtest->psa_status != PSA_SUCCESS) {
			res = ERR_CODE(API_STATUS_NOK);
			goto exit;
		}
	}

	if (!encrypt_op && aead_id != INT_MAX) {
		res = util_aead_find_node(list_aead_output(subtest), aead_id,
					  NULL, NULL, NULL, NULL, &iv.data,
					  &iv.length, false);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else {
		/* Read IV buffer */
		res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex,
					  subtest->params);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto exit;
	}

	/*
	 * Either set the nonce/iv if defined or generate it if length
	 * specified.
	 * Else can be set by the AEAD_SET_NONCE command in the test
	 * description.
	 */
	if (iv.data) {
		subtest->psa_status =
			psa_aead_set_nonce(&operation, iv.data, iv.length);
	} else if (iv.length) {
		iv.data = malloc(iv.length);
		if (!iv.data) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		subtest->psa_status =
			psa_aead_generate_nonce(&operation, iv.data, iv.length,
						&iv_length);

		if (subtest->psa_status == PSA_SUCCESS)
			SET_OVERFLOW(iv_length, iv.length);
	}

	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (encrypt_op && iv.data && aead_id != INT_MAX) {
		res = util_aead_add_data(list_aead_output(subtest), aead_id,
					 NULL, 0, NULL, 0, iv.data, iv.length);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

	res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
				    operation.op_context);

exit:
	tmp_res = aead_abort_op(res, subtest, &operation);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	if ((encrypt_op || aead_id == INT_MAX) && iv.data)
		free(iv.data);

	if (aad.data)
		free(aad.data);

	return res;
}

/**
 * aead_update_aad_psa() - Pass additional data to an active PSA AEAD operation
 * @subtest: Subtest data
 *
 * Return:
 * PASSED                   - Success
 * -BAD_ARGS                - Bad arguments
 * -API_STATUS_NOK          - PSA API call returned an error
 * Error code from util_context_set_op_ctx
 */
int aead_update_aad_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	struct smw_op_context *context = NULL;
	struct tbuffer aad = { 0 };
	psa_aead_operation_t operation = psa_aead_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&aad, AAD_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Failed to read AAD buffer");
		goto exit;
	}

	operation.op_context = context;

	subtest->psa_status =
		psa_aead_update_ad(&operation, aad.data, aad.length);
	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

	if (operation.op_context != context) {
		tmp_res =
			util_context_update_node(list_op_ctxs(subtest), ctx_id,
						 operation.op_context);
		if (res == ERR_CODE(PASSED) && tmp_res != ERR_CODE(PASSED))
			res = tmp_res;
	}

exit:
	if (aad.data)
		free(aad.data);

	tmp_res = aead_abort_op(res, subtest, &operation);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

/**
 * aead_update_psa() - Encrypt or decrypt a data fragment in an active PSA AEAD
 *                     operation
 * @subtest: Subtest data
 *
 * Reads input data and output parameters from the JSON definition, calls
 * psa_aead_update() and optionally saves the output into the AEAD output list
 * when "save_output" is set to true.
 *
 * Return:
 * PASSED                   - Success
 * -BAD_ARGS                - Bad arguments
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * -API_STATUS_NOK          - PSA API call returned an error
 * Error code from util_context_set_op_ctx
 */
int aead_update_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	int aead_id = INT_MAX;
	struct smw_op_context *context = NULL;
	struct tbuffer input = { 0 };
	struct tbuffer exp_output = { 0 };
	struct tbuffer output = { 0 };
	size_t output_length = 0;
	psa_aead_operation_t operation = psa_aead_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read aead_id for saving multipart encryption output */
	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/*
	 * Get the input to perform, if the input buffer is not filled,
	 * and the aead_id is given, get the input value from saved output
	 * of the previous AEAD operation.
	 */
	res = util_read_json_type(&input, INPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) ||
	    input.length > UINT32_MAX - PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE) {
		DBG_PRINT("Failed to read input buffer");
		goto exit;
	}

	if (aead_id != INT_MAX) {
		/* Free input.data as it will be overwritten */
		if (input.data) {
			free(input.data);
			input.data = NULL;
		}

		res = util_aead_get_part_output_node(list_aead_output(subtest),
						     aead_id, &input.data,
						     input.length);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

	/* Read expected output / output length */
	res = util_read_json_type(&exp_output, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read output buffer");
		goto exit;
	}

	if (res == ERR_CODE(VALUE_NOTFOUND) || !exp_output.length)
		output.length = PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input.length);
	else
		output.length = exp_output.length;

	if (output.length) {
		output.data = calloc(1, output.length);
		if (!output.data) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		if (!exp_output.length && exp_output.data)
			output.length = 0;
	}

	operation.op_context = context;

	subtest->psa_status =
		psa_aead_update(&operation, input.data, input.length,
				output.data, output.length, &output_length);

	if (operation.op_context != context) {
		tmp_res =
			util_context_update_node(list_op_ctxs(subtest), ctx_id,
						 operation.op_context);
		if (tmp_res != ERR_CODE(PASSED)) {
			if (subtest->psa_status == PSA_SUCCESS)
				res = tmp_res;
		}
	}

	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = util_compare_buffers(output.data, output_length, exp_output.data,
				   exp_output.length);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Output data does not match expected");
		goto exit;
	}

	res = util_aead_update_save_out_data(subtest, output.data,
					     output_length, ctx_id);

exit:
	if (aead_id == INT_MAX && input.data)
		free(input.data);

	if (output.data)
		free(output.data);

	if (exp_output.data)
		free(exp_output.data);

	tmp_res = aead_abort_op(res, subtest, &operation);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

/**
 * aead_final_psa() - Finish a multi-part PSA AEAD operation
 * @subtest: Subtest data
 *
 * For encryption, calls psa_aead_finish() and optionally saves combined
 * ciphertext + tag to the AEAD output list when "aead_id" is set.
 * For decryption, calls psa_aead_verify() with the provided tag.
 * If expected output is set, accumulated data from previous UPDATE calls is
 * compared against the expected value.
 *
 * Return:
 * PASSED                   - Success
 * -BAD_ARGS                - Bad arguments
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * -API_STATUS_NOK          - PSA API call returned an error
 * Error code from util_context_set_op_ctx
 */
int aead_final_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	struct smw_op_context *context = NULL;
	struct tbuffer tag = { 0 };
	struct tbuffer exp_output = { 0 };
	struct tbuffer output = { 0 };
	size_t output_length = 0;
	size_t tag_length = 0;
	int aead_id = INT_MAX;
	bool encrypt_op = false;
	bool tag_field_set = false;
	psa_aead_operation_t operation = psa_aead_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	res = is_aead_encrypt(subtest, &encrypt_op);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Read expected output */
	res = util_read_json_type(&exp_output, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read output buffer");
		goto exit;
	}

	if (res == ERR_CODE(VALUE_NOTFOUND))
		output.length = encrypt_op ? PSA_AEAD_FINISH_OUTPUT_MAX_SIZE :
					     PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE;
	else
		output.length = exp_output.length;

	/* Read aead_id for saving multipart encryption output */
	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Read 'tag_field_set' parameter, if any */
	res = util_read_json_type(&tag_field_set, TAG_FIELD_SET_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	operation.op_context = context;

	if (encrypt_op) {
		/* Read expected tag length if set */
		res = util_read_json_type(&tag, TAG_OBJ, t_buffer_hex,
					  subtest->params);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto exit;

		if (res == ERR_CODE(VALUE_NOTFOUND)) {
			tag.length = PSA_AEAD_TAG_MAX_SIZE;
			res = ERR_CODE(PASSED);
		}

		if (tag.length) {
			tag.data = malloc(tag.length);
			if (!tag.data) {
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto exit;
			}
		}

		if (output.length) {
			output.data = calloc(1, output.length);
			if (!output.data) {
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto exit;
			}
		}

		subtest->psa_status =
			psa_aead_finish(&operation, output.data, output.length,
					&output_length, tag.data, tag.length,
					&tag_length);

		if (subtest->psa_status == PSA_SUCCESS) {
			if (!output.length) {
				DBG_PRINT("Get output length = %u bytes",
					  output_length);
				DBG_PRINT("Get tag length = %u bytes",
					  tag_length);
			}
		}
	} else {
		if (aead_id != INT_MAX) {
			res = util_aead_find_node(list_aead_output(subtest),
						  aead_id, NULL, NULL,
						  &tag.data, &tag.length, NULL,
						  NULL, tag_field_set);
			if (res != ERR_CODE(PASSED))
				goto exit;
		}

		if (!tag_field_set) {
			res = util_read_json_type(&tag, TAG_OBJ, t_buffer_hex,
						  subtest->params);
			if (res != ERR_CODE(PASSED) &&
			    res != ERR_CODE(VALUE_NOTFOUND)) {
				DBG_PRINT("Failed to read tag buffer");
				goto exit;
			}
		}

		if (output.length) {
			output.data = calloc(1, output.length);
			if (!output.data) {
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto exit;
			}
		}

		subtest->psa_status =
			psa_aead_verify(&operation, output.data, output.length,
					&output_length, tag.data, tag.length);
	}

	if (operation.op_context != context) {
		tmp_res =
			util_context_update_node(list_op_ctxs(subtest), ctx_id,
						 operation.op_context);
		if (tmp_res != ERR_CODE(PASSED)) {
			if (subtest->psa_status == PSA_SUCCESS)
				res = tmp_res;
		}
	}

	if (subtest->psa_status != PSA_SUCCESS) {
		if (subtest->psa_status == PSA_ERROR_BUFFER_TOO_SMALL) {
			DBG_PRINT("expected output length %u", output_length);

			if (encrypt_op)
				DBG_PRINT("expected tag length %u", tag_length);
		}

		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	/*
	 * Save the output fragment from this final call into the AEAD list so
	 * that the total accumulated output can be compared with exp_output.
	 */
	res = util_aead_update_save_out_data(subtest, output.data,
					     output_length, ctx_id);

	if (res != ERR_CODE(PASSED))
		goto exit;

	/* If expected output is defined, compare total accumulated output */
	if (exp_output.data) {
		res = util_aead_cmp_output_data(list_aeads(subtest), ctx_id,
						exp_output.data,
						exp_output.length);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

	/*
	 * For encryption with aead_id set: save combined ciphertext + tag
	 * (collected across UPDATE calls plus this FINAL output) for later
	 * use in a cross-validation one-shot decryption.
	 */
	if (encrypt_op && aead_id != INT_MAX) {
		struct aead_output_data *node_data = NULL;

		res = util_list_find_node(list_aeads(subtest), ctx_id,
					  (void **)&node_data);
		if (res != ERR_CODE(PASSED))
			goto exit;

		if (!node_data) {
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		res = util_aead_add_data(list_aead_output(subtest), aead_id,
					 node_data->output,
					 node_data->output_len, tag.data,
					 tag_length, NULL, 0);
	}

exit:
	if (output.data)
		free(output.data);

	if (exp_output.data)
		free(exp_output.data);

	if (!tag_field_set && tag.data)
		free(tag.data);

	tmp_res = aead_abort_op(res, subtest, &operation);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int aead_set_lengths_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	struct smw_op_context *context = NULL;
	unsigned int plaintext_length = 0;
	struct tbuffer aad = { 0 };
	psa_aead_operation_t operation = psa_aead_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&aad, AAD_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Failed to read AAD");
		goto exit;
	}

	res = util_read_json_type(&plaintext_length, PLAINTEXT_LEN_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Failed to read AEAD plaintext length");
		goto exit;
	}

	operation.op_context = context;

	subtest->psa_status =
		psa_aead_set_lengths(&operation, aad.length, plaintext_length);

	if (operation.op_context != context) {
		tmp_res =
			util_context_update_node(list_op_ctxs(subtest), ctx_id,
						 operation.op_context);
		if (res == ERR_CODE(PASSED) && tmp_res != ERR_CODE(PASSED))
			res = tmp_res;
	}

	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	if (aad.data)
		free(aad.data);

	tmp_res = aead_abort_op(res, subtest, &operation);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int aead_set_nonce_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	int aead_id = INT_MAX;
	struct smw_op_context *context = NULL;
	struct tbuffer iv = { 0 };
	size_t iv_length = 0;
	psa_aead_operation_t operation = psa_aead_operation_init();
	bool encrypt_op = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read aead_id for saving multipart encryption output */
	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = is_aead_encrypt(subtest, &encrypt_op);
	if (res != ERR_CODE(PASSED))
		goto exit;

	operation.op_context = context;

	if (iv.data) {
		/* Explicit nonce provided: use psa_aead_set_nonce() */
		subtest->psa_status =
			psa_aead_set_nonce(&operation, iv.data, iv.length);
	} else {
		/*
		 * No hex buffer: read iv as a plain integer length, or fall
		 * back to PSA_AEAD_NONCE_MAX_SIZE when absent.
		 */
		res = util_read_json_type(&iv.length, IV_OBJ, t_uint,
					  subtest->params);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto exit;

		if (!iv.length)
			iv.length = PSA_AEAD_NONCE_MAX_SIZE;

		iv.data = malloc(iv.length);
		if (!iv.data) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		subtest->psa_status =
			psa_aead_generate_nonce(&operation, iv.data, iv.length,
						&iv_length);

		if (subtest->psa_status == PSA_SUCCESS)
			SET_OVERFLOW(iv_length, iv.length);
	}

	if (operation.op_context != context) {
		tmp_res =
			util_context_update_node(list_op_ctxs(subtest), ctx_id,
						 operation.op_context);
		if (res == ERR_CODE(PASSED) && tmp_res != ERR_CODE(PASSED))
			res = tmp_res;
	}

	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

	if (encrypt_op && iv.data && aead_id != INT_MAX) {
		res = util_aead_add_data(list_aead_output(subtest), aead_id,
					 NULL, 0, NULL, 0, iv.data, iv.length);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

exit:
	if (iv.data)
		free(iv.data);

	tmp_res = aead_abort_op(res, subtest, &operation);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int aead_abort_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	struct smw_op_context *context = NULL;
	psa_aead_operation_t operation = psa_aead_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	operation.op_context = context;

	subtest->psa_status = psa_aead_abort(&operation);
	if (subtest->psa_status == PSA_SUCCESS) {
		if (operation.op_context != context)
			res = util_context_update_node(list_op_ctxs(subtest),
						       ctx_id,
						       operation.op_context);
	} else {
		res = ERR_CODE(API_STATUS_NOK);
	}

	return res;
}
