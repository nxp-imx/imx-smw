/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __STATUS_PSA_H__
#define __STATUS_PSA_H__

#include "util_status.h"

/**
 * get_psa_status_codes() - Get the PSA status codes table.
 *
 * Return:
 * Pointer to the PSA status code table.
 */
const struct api_status_codes *get_psa_status_codes(void);

#endif /* __STATUS_PSA_H__ */
