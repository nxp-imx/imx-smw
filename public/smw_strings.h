/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
 */

#ifndef __SMW_STRINGS_H__
#define __SMW_STRINGS_H__

typedef const char *smw_string_t;

/**
 * typedef smw_kdf_t - Key derivation function name
 * Values:
 *	- TLS12_KEY_EXCHANGE
 *	- HKDF
 */
typedef smw_string_t smw_kdf_t;

/**
 * typedef smw_lifecycle_t - Device lifecycle name
 * Values:
 *	- OPEN
 *	- CLOSED
 *	- CLOSED_LOCKED
 *	- OEM_RETURN
 *	- NXP_RETURN
 */
typedef smw_string_t smw_lifecycle_t;

#endif /* __SMW_STRINGS_H__ */
