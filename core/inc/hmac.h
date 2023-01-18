/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023 NXP
 */

/**
 * struct smw_crypto_hmac_args - HMAC arguments
 * @key_descriptor: Descriptor of the Key
 * @algo_id: Algorithm ID
 * @pub: Pointer to the public API arguments structure
 *
 */
struct smw_crypto_hmac_args {
	/* Inputs */
	struct smw_keymgr_descriptor key_descriptor;
	enum smw_config_hmac_algo_id algo_id;
	struct smw_hmac_args *pub;
};
