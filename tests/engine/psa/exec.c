// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>

#include "util.h"
#include "util_debug.h"
#include "hash.h"
#include "rng.h"

/**
 * execute_hash_cmd() - Execute hash command.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hash().
 */
static int execute_hash_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return hash_psa(subtest);
}

/**
 * execute_rng_cmd() - Execute RNG command.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hash().
 */
static int execute_rng_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return rng_psa(subtest);
}

int execute_command_psa(char *cmd, struct subtest_data *subtest)
{
	static struct cmd_op {
		const char *cmd_prefix;
		int (*op)(char *cmd, struct subtest_data *subtest);
	} cmd_list[] = {
		{ HASH, &execute_hash_cmd },
		{ RNG, &execute_rng_cmd },
	};

	for (size_t idx = 0; idx < ARRAY_SIZE(cmd_list); idx++) {
		if (!strncmp(cmd, cmd_list[idx].cmd_prefix,
			     strlen(cmd_list[idx].cmd_prefix)))
			return cmd_list[idx].op(cmd, subtest);
	}

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}
