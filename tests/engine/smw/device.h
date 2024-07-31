/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */
#ifndef __DEVICE_H__
#define __DEVICE_H__

#include "types.h"

/**
 * device_get_lifecycle_name() - Convert lifecycle string value into integer value.
 * @string: Lifecycle string.
 *
 * Return:
 * Lifecycle name.
 */
smw_lifecycle_t device_get_lifecycle_name(const char *string);

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

/**
 * device_lifecycle() - Get/set the device lifecycle
 * @subtest: Subtest data.
 * @set: True if operation to set the device lifecycle
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
int device_lifecycle(struct subtest_data *subtest, bool set);

/**
 * device_reprovision() - Storage reprovisioning
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -API_STATUS_NOK          - SMW API Call return error
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 */
int device_reprovision(struct subtest_data *subtest);

#endif /* __DEVICE_H__ */
