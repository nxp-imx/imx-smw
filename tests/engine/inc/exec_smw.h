/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __EXEC_SMW_H__
#define __EXEC_SMW_H__

#include "types.h"

/**
 * execute_command_smw() - Execute a subtest command with SMW API.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Other error code otherwise.
 */
int execute_command_smw(char *cmd, struct subtest_data *subtest);

#endif /* __EXEC_SMW_H__ */
