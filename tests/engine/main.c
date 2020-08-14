// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "util.h"
#include "keymgr.h"
#include "crypto.h"
#include "types.h"

int main(int argc, char *argv[])
{
	int res = 1;
	unsigned int subtest = 1;
	char *input = NULL;
	char *command_name = NULL;
	json_object *obj = NULL;
	json_object *command = NULL;
	struct json_object_iter iter = { 0 };
	struct key_identifier_list *key_identifiers = NULL;

	if (argc < 2)
		return res;

	res = copy_file_into_buffer(argv[1], &input);
	if (res)
		return res;

	printf("Test vector is is:\n%s\n", input);

	obj = json_tokener_parse(input);
	if (!obj) {
		printf("Can't parse json input file\n");
		res = 1;
		goto exit;
	}

	json_object_object_foreachC(obj, iter)
	{
		if (strncmp(iter.key, JSON_SUBTEST, JSON_SUBTEST_LEN) ||
		    json_object_get_type(iter.val) != json_type_object ||
		    !json_object_object_get_ex(iter.val, CMD_OBJ, &command)) {
			printf("Subtest #%d: test vector is not good\n",
			       subtest);
			res = 1;
			break;
		}

		command_name = (char *)json_object_get_string(command);

		if (!strcmp(command_name, GENERATE_CMD)) {
			res = generate_key(iter.val, &key_identifiers);
		} else if (!strcmp(command_name, DELETE_CMD)) {
			res = delete_key(iter.val, key_identifiers);
		} else if (!strcmp(command_name, HASH_CMD)) {
			res = hash(iter.val);
		} else {
			printf("Undefined command\n");
			res = 1;
		}

		if (res) {
			printf("Subtest #%d failed. Test is aborted\n",
			       subtest);
			break;
		}

		subtest++;
	}

	key_identifier_clear_list(key_identifiers);

exit:
	free(input);

	return res;
}
