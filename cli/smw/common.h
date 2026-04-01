/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_SMW_COMMON_H
#define CLI_SMW_COMMON_H

#include <smw_crypto.h>
#include <stdbool.h>

const char *cli_smw_get_subsystem_name(smw_subsystem_t subsystem);
bool is_smw_api_success(const char *func, enum smw_status_code status);

#endif /* CLI_SMW_COMMON_H */
