// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>

#include "util.h"
#include "util_debug.h"
#include "keymgr.h"
#include "hash.h"
#include "rng.h"

/**
 * execute_delete_key_cmd() - Execute delete key command.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * Error code from delete_key().
 */
static int execute_delete_key_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return delete_key_psa(subtest);
}

/**
 * execute_generate_cmd() - Execute generate key command.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED          - Passed.
 * -MISSING_PARAMS - Subsystem missing
 * Error code from generate_key().
 */
static int execute_generate_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return generate_key_psa(subtest);
}

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
 * execute_import_cmd() - Execute import key command.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from import_key().
 */
static int execute_import_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return import_key_psa(subtest);
}

/**
 * execute_export_cmd() - Execute export command.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from export_key().
 */
static int execute_export_cmd(char *cmd, struct subtest_data *subtest)
{
	if (!strcmp(cmd, EXPORT_KEYPAIR))
		return export_key_psa(subtest, EXP_KEYPAIR);
	else if (!strcmp(cmd, EXPORT_PRIVATE))
		return export_key_psa(subtest, EXP_PRIV);
	else if (!strcmp(cmd, EXPORT_PUBLIC))
		return export_key_psa(subtest, EXP_PUB);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
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

/**
 * execute_get_key_attrs_cmd() - Execute get key attibutes command
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Success.
 * -BAD_RESULT		- SMW API status differs from expected one.
 * -BAD_ARGS		- One of the arguments is bad.
 * -BAD_PARAM_TYPE	- A parameter value is undefined.
 * -VALUE_NOTFOUND	- Test definition Value not found.
 * -FAILED		- Test failed
 */
static int execute_get_key_attrs_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return get_key_attributes_psa(subtest);
}

int execute_command_psa(char *cmd, struct subtest_data *subtest)
{
	static struct cmd_op {
		const char *cmd_prefix;
		int (*op)(char *cmd, struct subtest_data *subtest);
	} cmd_list[] = {
		{ DELETE, &execute_delete_key_cmd },
		{ GENERATE, &execute_generate_cmd },
		{ IMPORT, &execute_import_cmd },
		{ EXPORT, &execute_export_cmd },
		{ HASH, &execute_hash_cmd },
		{ RNG, &execute_rng_cmd },
		{ GET_KEY_ATTRIBUTES, &execute_get_key_attrs_cmd },
	};

	for (size_t idx = 0; idx < ARRAY_SIZE(cmd_list); idx++) {
		if (!strncmp(cmd, cmd_list[idx].cmd_prefix,
			     strlen(cmd_list[idx].cmd_prefix)))
			return cmd_list[idx].op(cmd, subtest);
	}

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}
