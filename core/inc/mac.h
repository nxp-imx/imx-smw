/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __MAC_H__
#define __MAC_H__

#include "smw_crypto.h"

#include "keymgr.h"

/**
 * struct smw_crypto_mac_args - MAC arguments
 * @key_descriptor: Descriptor of the Key
 * @algo_id: Algorithm ID
 * @hash_id: Hash algorithm ID
 * @op_id: Operation ID
 * @pub: Pointer to the public API arguments structure
 *
 */
struct smw_crypto_mac_args {
	/* Inputs */
	struct smw_keymgr_descriptor key_descriptor;
	enum smw_config_mac_algo_id algo_id;
	enum smw_config_hash_algo_id hash_id;
	enum smw_config_mac_op_type_id op_id;
	struct smw_mac_args *pub;
};

#endif /* __MAC_H__ */
