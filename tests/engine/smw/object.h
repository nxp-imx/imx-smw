/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */
#ifndef __OBJECT_H__
#define __OBJECT_H__

#include "types.h"

/**
 * object_find() - Find object
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error.
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory.
 * -MISSING_PARAMS          - One argument is missing.
 */
int object_find(struct subtest_data *subtest);

#endif /* __OBJECT_H__ */
