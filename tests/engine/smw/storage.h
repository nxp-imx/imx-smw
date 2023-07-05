/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __STORAGE_H__
#define __STORAGE_H__

#include "types.h"

/**
 * storage_store() - Store data
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory.
 * -MISSING_PARAMS          - One argument is missing.
 */
int storage_store(struct subtest_data *subtest);

/**
 * storage_retrieve() - Retrieve data
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory.
 */
int storage_retrieve(struct subtest_data *subtest);

/**
 * storage_delete() - Delete data
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
int storage_delete(struct subtest_data *subtest);

#endif /* __STORAGE_H__ */
