/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SMW_CRYPTO_MAC_H__
#define __SMW_CRYPTO_MAC_H__

/**
 * struct smw_mac_args - MAC arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @key_descriptor: [in] Pointer to a Key descriptor object.
 *                  See &struct smw_key_descriptor.
 * @algo_name: [in] MAC algorithm name. See &typedef smw_mac_algo_t.
 * @hash_name: [in] Hash algorithm name. See &typedef smw_hash_algo_t.
 * @input: [in] Pointer to the message to be authenticated.
 * @input_length: [in] Length in bytes of the message.
 * @mac:
 *  - [in] Pointer to the MAC buffer to compare.
 *  - [out] Pointer to the MAC buffer to be written.
 * @mac_length:
 *  - [in] Length in bytes of the MAC buffer to compare.
 *  - [out] Length in bytes of the MAC buffer generated.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the default one defined in the library configuration
 * or it's the one handling the key is key identifier is defined.
 */
struct smw_mac_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_mac_algo_t algo_name;
	smw_hash_algo_t hash_name;
	unsigned char *input;
	unsigned int input_length;
	unsigned char *mac;
	unsigned int mac_length;
};

/**
 * smw_mac() - Compute a MAC.
 * @args: Pointer to the structure that contains the MAC arguments.
 *
 * This function computes a Message Authentication Code using a key present in
 * the Secure Subsystem storage identified by the key_descriptor identifier
 * or a plaintext key value filled in the key descriptor private buffer.
 *
 * To query the required MAC buffer length, set @args->mac to NULL. The function
 * will then set the required MAC buffer length in @args->mac_length and return
 * SMW_STATUS_OK.
 *
 * On operation completion, the @args->mac_length is updated to the correct
 * value when:\
 *
 *  - MAC buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - MAC buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->input is NULL and @args->input_length is not 0.
 *      - @args->input is not NULL and @args->input_length is 0.
 *      - @args->mac is NULL and @args->mac_length is not 0.
 *      - @args->mac is not NULL and @args->mac_length is 0.
 *      - In case of using plaintext key, private buffer is NULL or length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_mac(struct smw_mac_args *args);

/**
 * smw_mac_verify() - Compute and verify a MAC.
 * @args: Pointer to the structure that contains the MAC arguments.
 *
 * This function computes then verifies a Message Authentication Code using a
 * key present in the Secure Subsystem storage identified by the
 * key_descriptor or a plaintext key value filled in the key descriptor
 * private buffer.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->input is NULL and @args->input_length is not 0.
 *      - @args->input is not NULL and @args->input_length is 0.
 *      - @args->mac is NULL and @args->mac_length is not 0.
 *      - @args->mac is not NULL and @args->mac_length is 0.
 *      - In case of using plaintext key, private buffer is NULL or length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_mac_verify(struct smw_mac_args *args);

#endif /* __SMW_CRYPTO_MAC_H__ */
