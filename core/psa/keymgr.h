/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KEYMGR__H__
#define __KEYMGR__H__

#include "smw_strings.h"

#include "psa/crypto_types.h"

/**
 * get_psa_key_type() - Get PSA key type.
 * @smw_key_type: SMW key type name.
 *
 * This function returns the PSA key type corresponding to the SMW key type.
 *
 * Return:
 * PSA key type.
 */
psa_key_type_t get_psa_key_type(smw_key_type_t smw_key_type);

#endif /* __KEYMGR__H__ */
