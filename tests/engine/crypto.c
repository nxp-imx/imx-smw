// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "util.h"
#include "crypto.h"
#include "types.h"
#include "smw_crypto.h"
#include "smw_status.h"

/**
 * struct hash
 * @algo_name: Hash algo name.
 * @digest_len: @algo_name digest len in bytes.
 */
static struct hash {
	const char *algo_name;
	unsigned int digest_len;
} hash_size[] = { { .algo_name = "MD5", .digest_len = 16 },
		  { .algo_name = "SHA1", .digest_len = 20 },
		  { .algo_name = "SHA224", .digest_len = 28 },
		  { .algo_name = "SHA256", .digest_len = 32 },
		  { .algo_name = "SHA384", .digest_len = 48 },
		  { .algo_name = "SHA512", .digest_len = 64 },
		  { .algo_name = "SM3", .digest_len = 32 } };

static int get_hash_digest_len(char *algo)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(hash_size);

	for (; i < array_size; i++) {
		if (!strcmp(algo, hash_size[i].algo_name))
			return hash_size[i].digest_len;
	}

	return 0;
}

int hash(json_object *args)
{
	int status = 1;
	int expected_result = SMW_STATUS_OPERATION_FAILURE;
	unsigned int output_len = 0;
	char *string_input = NULL;
	char *digest_string = NULL;
	unsigned char *hex_message = NULL;
	unsigned char *output = NULL;
	unsigned char *expected_digest = NULL;
	struct smw_hash_args hash_args = { 0 };
	json_object *version = NULL;
	json_object *subsystem = NULL;
	json_object *algo = NULL;
	json_object *input = NULL;
	json_object *input_len = NULL;
	json_object *result = NULL;
	json_object *digest = NULL;

	/* Get hash args objects */
	json_object_object_get_ex(args, VERSION_OBJ, &version);
	json_object_object_get_ex(args, SUBSYSTEM_OBJ, &subsystem);
	json_object_object_get_ex(args, ALGO_OBJ, &algo);
	json_object_object_get_ex(args, INPUT_OBJ, &input);
	json_object_object_get_ex(args, INPUT_LEN_OBJ, &input_len);
	json_object_object_get_ex(args, RES_OBJ, &result);

	/* Fill hash args */
	hash_args.version = json_object_get_int(version);
	hash_args.subsystem_name = json_object_get_string(subsystem);
	hash_args.algo_name = json_object_get_string(algo);
	hash_args.input_length = json_object_get_int(input_len);

	if (hash_args.input_length) {
		hex_message = malloc(hash_args.input_length);
		if (!hex_message) {
			printf("ERROR in %s. Memory allocation failed\n",
			       __func__);
			goto exit;
		}
	}

	/* Convert input string in hex values */
	string_input = (char *)json_object_get_string(input);
	convert_string_to_hex(string_input, hex_message,
			      hash_args.input_length);
	hash_args.input = hex_message;

	output_len = get_hash_digest_len((char *)hash_args.algo_name);
	/*
	 * Output len can be 0. For example: test with a bad algo name config.
	 * In this case don't need to allocate output buffer
	 */
	if (output_len) {
		output = malloc(output_len);
		if (!output) {
			printf("ERROR in %s. Memory allocation failed\n",
			       __func__);
			goto exit;
		}
	}

	hash_args.output = output;
	hash_args.output_length = output_len;

	/* Call hash function and compare result with expected one */
	status = smw_hash(&hash_args);
	expected_result = json_object_get_int(result);

	if (status != expected_result) {
		printf("ERROR in %s. Result is %d and should be %d\n", __func__,
		       status, expected_result);
		status = 1;
		goto exit;
	}

	/* If hash operation succeeded, compare digest with expected one */
	if (!status) {
		expected_digest = malloc(output_len);
		if (!expected_digest) {
			printf("ERROR in %s. Memory allocation failed\n",
			       __func__);
			status = 1;
			goto exit;
		}

		json_object_object_get_ex(args, DIGEST_OBJ, &digest);
		digest_string = (char *)json_object_get_string(digest);
		/* Convert digest string in hex values */
		convert_string_to_hex(digest_string, expected_digest,
				      output_len);

		if (strcmp((char *)expected_digest, (char *)output)) {
			printf("ERROR in %s. Digest is bad\n", __func__);
			status = 1;
			goto exit;
		}
	}

	status = 0;

exit:
	if (hex_message)
		free(hex_message);

	if (output)
		free(output);

	if (expected_digest)
		free(expected_digest);

	return status;
}
