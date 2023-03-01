/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __EXEC_PSA_H__
#define __EXEC_PSA_H__

#include "types.h"

/**
 * execute_command_psa() - Execute a subtest command with PSA API.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Other error code otherwise.
 */
int execute_command_psa(char *cmd, struct subtest_data *subtest);

#endif /* __EXEC_PSA_H__ */
