/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __RUN_H__
#define __RUN_H__

#define SUBTEST_STATUS_PASSED_MAX_LEN 30

/**
 * run_test() - Run a test.
 * @test_definition_file: Name of the test definition file.
 * @test_name: Test name.
 * @output_dir: Path to output test status directory. If NULL, the default
 *              path DEFAULT_OUT_STATUS_PATH is used.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL			- Internal error.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * Error code from file_to_json_object().
 */
int run_test(char *test_definition_file, char *test_name, char *output_dir);

#endif /* __RUN_H__ */
