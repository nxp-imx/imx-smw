// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024, 2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "hash.h"
#include "json_types.h"
#include "util.h"
#include "util_context.h"

#define HASH_ALGO(_name, _id, _length)                                         \
	{                                                                      \
		.name = _name, .psa_alg_id = PSA_ALG_##_id, .length = _length  \
	}

/**
 * struct hash_alg_info
 * @name: Hash algorithm name.
 * @psa_alg_id: PSA hash algorithm id.
 * @length: @name digest length in bytes.
 */
static const struct hash_alg_info {
	const char *name;
	psa_algorithm_t psa_alg_id;
	size_t length;
} hash_alg_info[] = { HASH_ALGO("MD5", MD5, 16),
		      HASH_ALGO("SHA1", SHA_1, 20),
		      HASH_ALGO("SHA224", SHA_224, 28),
		      HASH_ALGO("SHA256", SHA_256, 32),
		      HASH_ALGO("SHA384", SHA_384, 48),
		      HASH_ALGO("SHA512", SHA_512, 64),
		      HASH_ALGO("SHA3_224", SHA3_224, 28),
		      HASH_ALGO("SHA3_256", SHA3_256, 32),
		      HASH_ALGO("SHA3_384", SHA3_384, 48),
		      HASH_ALGO("SHA3_512", SHA3_512, 64),
		      HASH_ALGO("SM3", SM3, 32),
		      HASH_ALGO(NULL, NONE, 0) };

static const struct hash_alg_info *get_hash_alg_info(const char *alg_name)
{
	return GET_INFO(alg_name, hash_alg_info);
}

psa_algorithm_t get_hash_alg_id(const char *alg_name)
{
	const struct hash_alg_info *info = get_hash_alg_info(alg_name);

	if (!info)
		return PSA_ALG_NONE;

	return info->psa_alg_id;
}

static size_t get_hash_length(const char *alg_name)
{
	const struct hash_alg_info *info = get_hash_alg_info(alg_name);

	if (!info)
		return 0;

	return info->length;
}

int hash_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	const char *alg_name = NULL;
	psa_algorithm_t psa_alg_id = PSA_ALG_NONE;
	unsigned int input_len = 0;
	unsigned int digest_len = 0;
	unsigned char *input_hex = NULL;
	unsigned char *digest_hex = NULL;
	size_t input_length = 0;
	uint8_t *input = NULL;
	size_t hash_size = 0;
	size_t hash_len = 0;
	uint8_t *hash = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Algorithm is mandatory */
	res = util_read_json_type(&alg_name, ALGO_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_read_hex_buffer(&input_hex, &input_len, subtest->params,
				   INPUT_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	input = input_hex;
	input_length = input_len;

	psa_alg_id = get_hash_alg_id(alg_name);
	hash_size = get_hash_length(alg_name);

	/*
	 * Read expected digest buffer if any.
	 * Test definition might not set the expected digest buffer.
	 */
	res = util_read_hex_buffer(&digest_hex, &digest_len, subtest->params,
				   DIGEST_OBJ);
	if (res == ERR_CODE(PASSED)) {
		if (digest_hex) {
			hash = malloc(hash_size);
			if (!hash) {
				DBG_PRINT_ALLOC_FAILURE();
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto exit;
			}
		}

		hash_size = digest_len;
	} else if (res == ERR_CODE(MISSING_PARAMS)) {
		if (SET_OVERFLOW(hash_size, digest_len)) {
			DBG_PRINT_BAD_PARAM(ALGO_OBJ);
			res = ERR_CODE(BAD_ARGS);
			goto exit;
		}
	} else {
		goto exit;
	}

	/* Call hash function and compare result with expected one */
	subtest->psa_status = psa_hash_compute(psa_alg_id, input, input_length,
					       hash, hash_size, &hash_len);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	/*
	 * If Hash operation succeeded and expected digest or digest length
	 * is set in the test definition file then compare operation result.
	 */
	hash_size = get_hash_length(alg_name);

	if (hash_size < digest_len) {
		if (SET_OVERFLOW(hash_size, digest_len)) {
			DBG_PRINT_BAD_PARAM(ALGO_OBJ);
			res = ERR_CODE(BAD_ARGS);
			goto exit;
		}
	}

	res = util_compare_buffers(hash, hash_len, digest_hex, digest_len);

exit:
	if (input_hex)
		free(input_hex);

	if (hash)
		free(hash);

	if (digest_hex)
		free(digest_hex);

	return res;
}

int hash_init_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	const char *alg_name = NULL;
	struct smw_op_context *context = NULL;
	psa_algorithm_t psa_alg_id = PSA_ALG_NONE;
	psa_hash_operation_t operation = psa_hash_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	if (context) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Algorithm is mandatory */
	res = util_read_json_type(&alg_name, ALGO_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	psa_alg_id = get_hash_alg_id(alg_name);

	/* Call hash function and compare result with expected one */
	subtest->psa_status = psa_hash_setup(&operation, psa_alg_id);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
				    operation.op_context);

exit:
	return res;
}

int hash_update_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	unsigned int input_len = 0;
	unsigned char *input_hex = NULL;
	struct smw_op_context *context = NULL;
	psa_hash_operation_t operation = psa_hash_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_hex_buffer(&input_hex, &input_len, subtest->params,
				   INPUT_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	operation.op_context = context;

	/* Call hash function and compare result with expected one */
	subtest->psa_status = psa_hash_update(&operation, input_hex, input_len);
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
	if (input_hex)
		free(input_hex);

	return res;
}

int hash_final_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	unsigned int output_len = PSA_HASH_MAX_SIZE;
	unsigned int digest_len = 0;
	size_t hash_length = 0;
	unsigned char *output_hex = NULL;
	unsigned char *digest_hex = NULL;
	struct smw_op_context *context = NULL;
	psa_hash_operation_t operation = psa_hash_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/*
	 * Read expected digest buffer if any.
	 * Test definition might not set the expected digest buffer.
	 */
	res = util_read_hex_buffer(&digest_hex, &digest_len, subtest->params,
				   DIGEST_OBJ);
	if (res == ERR_CODE(PASSED))
		output_len = digest_len;
	else if (res == ERR_CODE(MISSING_PARAMS))
		digest_len = output_len;
	else
		goto exit;

	output_hex = malloc(output_len);
	if (!output_hex) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	operation.op_context = context;

	/* Call hash function and compare result with expected one */
	subtest->psa_status = psa_hash_finish(&operation, output_hex,
					      output_len, &hash_length);
	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

	if (operation.op_context != context) {
		tmp_res =
			util_context_update_node(list_op_ctxs(subtest), ctx_id,
						 operation.op_context);

		if (res == ERR_CODE(PASSED) && tmp_res != ERR_CODE(PASSED)) {
			res = tmp_res;
			goto exit;
		}
	}

	if (res == ERR_CODE(PASSED))
		res = util_compare_buffers(output_hex, hash_length, digest_hex,
					   digest_len);

exit:
	if (output_hex)
		free(output_hex);

	if (digest_hex)
		free(digest_hex);

	return res;
}

int hash_verify_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	unsigned int digest_len = 0;
	unsigned char *digest_hex = NULL;
	struct smw_op_context *context = NULL;
	psa_hash_operation_t operation = psa_hash_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/*
	 * Read expected digest buffer.
	 */
	res = util_read_hex_buffer(&digest_hex, &digest_len, subtest->params,
				   DIGEST_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	operation.op_context = context;

	/* Call hash function and compare result with expected one */
	subtest->psa_status =
		psa_hash_verify(&operation, digest_hex, digest_len);
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
	if (digest_hex)
		free(digest_hex);

	return res;
}

int hash_clone_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	unsigned int dst_ctx_id = 0;
	unsigned int src_ctx_id = 0;
	struct smw_op_context *dst_context = NULL;
	struct smw_op_context *src_context = NULL;
	struct json_object *obj = NULL;
	psa_hash_operation_t src_operation = psa_hash_operation_init();
	psa_hash_operation_t dst_operation = psa_hash_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Context ID is a mandatory parameter */
	res = util_read_json_type(&obj, CTX_ID_OBJ, t_buffer, subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	if (obj) {
		/*
		 * Context ID must be an array of integer. First member
		 * represents the source ID, second the destination ID
		 */

		if (json_object_get_type(obj) != json_type_array) {
			DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		if (json_object_array_length(obj) != 2) {
			DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		/* Get source context ID and node data */
		res = util_context_array_find_node(subtest, obj, 0, &src_ctx_id,
						   &src_context);
		if (res != ERR_CODE(PASSED))
			return res;

		/* Get destination context ID and node data */
		res = util_context_array_find_node(subtest, obj, 1, &dst_ctx_id,
						   &dst_context);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	src_operation.op_context = src_context;

	/* Call hash clone function */
	subtest->psa_status = psa_hash_clone(&src_operation, &dst_operation);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = util_context_add_node(list_op_ctxs(subtest), dst_ctx_id,
				    dst_operation.op_context);

exit:
	return res;
}

int hash_abort_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	struct smw_op_context *context = NULL;
	psa_hash_operation_t operation = psa_hash_operation_init();

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	operation.op_context = context;

	/* Call hash function and compare result with expected one */
	subtest->psa_status = psa_hash_abort(&operation);
	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

	if (operation.op_context != context) {
		tmp_res =
			util_context_update_node(list_op_ctxs(subtest), ctx_id,
						 operation.op_context);

		if (res == ERR_CODE(PASSED) && tmp_res != ERR_CODE(PASSED))
			res = tmp_res;
	}

	return res;
}
