/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __KEYMGR__H__
#define __KEYMGR__H__

#include "smw_strings.h"

#include "psa/crypto_types.h"

/**
 * get_cipher_psa_key_type() - Get Cipher PSA key type.
 * @smw_key_type: SMW key type name.
 *
 * This function returns the Cipher PSA key type corresponding to the Cipher
 * SMW key type.
 *
 * Return:
 * Cipher PSA key type.
 */
psa_key_type_t get_cipher_psa_key_type(smw_key_type_t smw_key_type);

#endif /* __KEYMGR__H__ */
