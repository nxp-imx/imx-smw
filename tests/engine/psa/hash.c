// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "hash.h"
#include "json_types.h"
#include "util.h"

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
} hash_alg_info[] = {
	HASH_ALGO("MD5", MD5, 16),	  HASH_ALGO("SHA1", SHA_1, 20),
	HASH_ALGO("SHA224", SHA_224, 28), HASH_ALGO("SHA256", SHA_256, 32),
	HASH_ALGO("SHA384", SHA_384, 48), HASH_ALGO("SHA512", SHA_512, 64),
	HASH_ALGO("SM3", SM3, 32),	  HASH_ALGO(NULL, NONE, 0)
};

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
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	if (res == ERR_CODE(MISSING_PARAMS) || (hash_size && digest_hex)) {
		hash = malloc(hash_size);
		if (!hash) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}
	}

	if (res == ERR_CODE(PASSED))
		hash_size = digest_len;

	if (res == ERR_CODE(MISSING_PARAMS)) {
		if (SET_OVERFLOW(hash_size, digest_len)) {
			DBG_PRINT_BAD_PARAM(ALGO_OBJ);
			res = ERR_CODE(BAD_ARGS);
			goto exit;
		}
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
