/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_STATUS_H__
#define __UTIL_STATUS_H__

/**
 * util_smw_to_psa_status() - Convert SMW status to PSA status.
 * @status: SMW status.
 *
 * Return:
 * psa_status_t.
 */
psa_status_t util_smw_to_psa_status(enum smw_status_code status);

#endif /* __UTIL_STATUS_H__ */
