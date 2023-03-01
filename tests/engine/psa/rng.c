// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "rng.h"
#include "util.h"

int rng_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct tbuffer random = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_read_json_type(&random, RANDOM_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (!is_api_test(subtest)) {
		/*
		 * In case of non API test, the test must specify only
		 * the "random" buffer length.
		 */
		if (!random.length || random.data) {
			DBG_PRINT_BAD_PARAM(RANDOM_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto exit;
		}

		random.data = malloc(random.length);
		if (!random.data) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		memset(random.data, 0, random.length);
	}

	/* Call RNG function */
	subtest->psa_status = psa_generate_random(random.data, random.length);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (!is_api_test(subtest)) {
		if (random.length <= 256)
			DBG_DHEX("Random number", random.data, random.length);

		/* Verify there is not zero value in the random bufffer */
		while (random.length--) {
			if (*(random.data + random.length))
				goto exit;
		}

		res = ERR_CODE(SUBSYSTEM);
	}

exit:
	if (random.data)
		free(random.data);

	return res;
}
