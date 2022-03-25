/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __RUN_APP_H__
#define __RUN_APP_H__

#include "util_app.h"

/**
 * process_app() - Process application routine
 * @app: Application data
 *
 * Return:
 * PASSED  - Application test passed
 * or any error code (see enum err_num)
 */
int process_app(struct app_data *app);

/**
 * run_apps() - Run all test's applications
 * @test: Overall test data
 *
 * Return:
 * PASSED  - All applications are running or passed
 * or any error code (see enum err_num)
 */
int run_apps(struct test_data *test);

#endif /* __RUN_APP_H__ */
