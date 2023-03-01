/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __STATUS_SMW_H__
#define __STATUS_SMW_H__

#include "util_status.h"

/**
 * get_smw_status_codes() - Get the SMW status codes table.
 *
 * Return:
 * Pointer to the SMW status code table.
 */
const struct api_status_codes *get_smw_status_codes(void);

#endif /* __STATUS_SMW_H__ */
