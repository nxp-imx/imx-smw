/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PSA_COMMON_H
#define CLI_PSA_COMMON_H

#include <stdbool.h>
#include <psa/crypto.h>

bool is_psa_api_success(const char *func, psa_status_t status);

#endif /* CLI_PSA_COMMON_H */
