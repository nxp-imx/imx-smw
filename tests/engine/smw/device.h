/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __DEVICE_H__
#define __DEVICE_H__

#include "types.h"

/**
 * device_uuid() - Get the device UUID
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
int device_uuid(struct subtest_data *subtest);

/**
 * device_attestation() - Get the device attestation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
int device_attestation(struct subtest_data *subtest);

#endif /* __DEVICE_H__ */
