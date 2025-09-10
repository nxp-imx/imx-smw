/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2025 NXP
 */

#ifndef __KEYMGR__H__
#define __KEYMGR__H__

#include "smw/names.h"
#include "smw/attr.h"

#include "psa/crypto_types.h"

/* Can derive at most 4 keys */
#define KEY_DERIVATION_MAX_KEYS (4)

/* Can derive at most 2 IVs, of 16 bytes each */
#define KEY_DERIVATION_MAX_IVS	 (2)
#define KEY_DERIVATION_MAX_IVLEN (16)

/**
 * struct psa_key_derivation_context_tls13 - TLS1.3 key derivation context structure
 *
 * @info: The TLS 1.3 key derivation context buffer.
 * @infolen: @info length in bytes.
 */
struct psa_key_derivation_context_tls13 {
	unsigned char *info;
	size_t infolen;
};

/**
 * struct psa_key_derivation_context_tls12 - TLS1.2 key derivation context structure
 *
 * @ctx: Secure subsystem operation context.
 * @seed: The input seed for TLS1.2 key derivation (concatenation of label,
 *                    client random and server random).
 * @seedlen: @seed length in bytes.
 * @done: Flag to indicate if TLS 1.2 key derivation is complete.
 * @keys: Array to store derived TLS1.2 key identifiers.
 * @nbkeys: Number of TLS1.2 derived keys, depending on the selected ciphersuite.
 * @keyidx: Current TLS1.2 derived key index during key derivation output.
 * @ivs: Array to store TLS1.2 derived IVs.
 * @ivlen: Length of each TLS1.2 derived IV, depending on the selected ciphersuite.
 * @iv: Current TLS1.2 derived IV index during key derivation output.
 *
 * The TLS1.2 key expansion is done in a single step, where all keys (2 or 4)
 * and all IVs (0 or 2) are being output.
 * With the PSA API, these can only be retrieved in multiple calls to e.g.
 * psa_key_derivation_output_key() and psa_key_derivation_output_bytes().
 *
 * The keys and IVs are stored here until they are retrieved via these functions.
 */
struct psa_key_derivation_context_tls12 {
	struct smw_op_context *ctx;
	unsigned char *seed;
	size_t seedlen;
	bool done;

	psa_key_id_t keys[KEY_DERIVATION_MAX_KEYS];
	size_t nbkeys;
	size_t keyidx;

	uint8_t ivs[KEY_DERIVATION_MAX_IVS][KEY_DERIVATION_MAX_IVLEN];
	size_t ivlen;
	size_t ividx;
};

/**
 * struct psa_key_derivation_context - Key derivation context structure
 *
 * This is a private structure that is allocated when psa_key_derivation_setup() is
 * called, and holds intermediary information during the key derivation process. It
 * is needed because PSA key derivation is a multi-step operation where data is being
 * input/output in multiple calls. A typical PSA key derivation flow is like this:
 *
 * * psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
 * * psa_key_derivation_setup(&op, ...);
 * * psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_STEP_INPUT_SECRET, ...);
 * * psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_STEP_INPUT_INFO, ...);
 * * psa_key_derivation_output_key(&op, ...);
 * * psa_key_derivation_output_bytes(&op, ...);
 * * psa_key_derivation_abort(&op, ...);
 *
 * @alg: A key derivation algorithm (PSA_ALG_XXX value such that
 *                   PSA_ALG_IS_KEY_DERIVATION(alg) is true).
 * @secret_id: The input secret key identifier.
 * @other_secret_id: Optional additional secret key identifier, used as input
 *                   with psa_key_derivation_key_agreement().
 * @peerbuf: Peer public key that is also an input for the key derivation with
 *                   psa_key_derivation_key_agreement().
 * @peerbuflen: @peerbuf length in bytes.
 *
 */
struct psa_key_derivation_context {
	psa_algorithm_t alg;

	psa_key_id_t secret_id;
	psa_key_id_t other_secret_id;

	unsigned char *peerbuf;
	size_t peerbuflen;

	union {
		struct psa_key_derivation_context_tls13 tls13;
		struct psa_key_derivation_context_tls12 tls12;
	};
};

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
