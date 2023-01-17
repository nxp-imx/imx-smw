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

/**
 * smw_mac_get_input_data() - Return the address of MAC input buffer.
 * @args: Pointer to the internal MAC args structure.
 *
 * This function returns the address of the MAC input buffer.
 *
 * Return:
 * NULL
 * address of the MAC input buffer.
 */
unsigned char *smw_mac_get_input_data(struct smw_crypto_mac_args *args);

/**
 * smw_mac_get_input_length() - Return the length of MAC input buffer.
 * @args: Pointer to the internal MAC args structure.
 *
 * This function returns the length of the MAC input buffer.
 *
 * Return:
 * 0
 * length of the MAC input buffer.
 */
unsigned int smw_mac_get_input_length(struct smw_crypto_mac_args *args);

/**
 * smw_mac_get_mac_data() - Return the address of MAC buffer.
 * @args: Pointer to the internal MAC args structure.
 *
 * This function returns the address of the MAC buffer.
 *
 * Return:
 * NULL
 * address of the MAC buffer.
 */
unsigned char *smw_mac_get_mac_data(struct smw_crypto_mac_args *args);

/**
 * smw_mac_get_mac_length() - Return the length of MAC buffer.
 * @args: Pointer to the internal MAC args structure.
 *
 * This function returns the length of the MAC buffer.
 *
 * Return:
 * 0
 * length of the MAC buffer.
 */
unsigned int smw_mac_get_mac_length(struct smw_crypto_mac_args *args);

/**
 * smw_mac_set_mac_length() - Set the length of MAC computed buffer.
 * @args: Pointer to the internal MAC args structure.
 * @mac_length: Length of the MAC computed buffer.
 *
 * This function sets the length of the MAC computed buffer.
 *
 * Return:
 * none.
 */
void smw_mac_set_mac_length(struct smw_crypto_mac_args *args,
			    unsigned int mac_length);

#endif /* __MAC_H__ */
