/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef PUBKEY_ENCODE_H
#define PUBKEY_ENCODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int pubkey_encode(const char *key_type, unsigned int bits, const uint8_t *raw,
		  size_t raw_len, const char *out_file, bool use_pem);

int pubkey_encode_rsa(unsigned int bits, const uint8_t *mod, size_t mod_len,
		      const uint8_t *exp, size_t exp_len, const char *out_file,
		      bool use_pem);

#endif /* PUBKEY_ENCODE_H */
