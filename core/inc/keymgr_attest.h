/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __KEYMGR_ATTEST_H__
#define __KEYMGR_ATTEST_H__

#include "keymgr.h"
#include "sign_verify.h"
/**
 * struct smw_keymgr_attest_args - Key attestation arguments
 * @key_descriptor: Descriptor of the Key to be attested
 * @attest_key_descriptor: Descriptor of the attestation Key
 * @sign_attributes: Signature algorithm and attributes
 * @pub: Pointer to the public key attestation arguments structure
 *
 */
struct smw_keymgr_attest_args {
	struct smw_keymgr_descriptor key_descriptor;
	struct smw_keymgr_descriptor attest_key_descriptor;
	struct smw_sign_verify_attributes sign_attributes;
	struct smw_key_attestation_args *pub;
};

/**
 * smw_keymgr_get_attest_chal() - Return the address of the challenge buffer.
 * @args: Pointer to the internal key attestation args structure.
 *
 * This function returns the address of the challenge buffer.
 *
 * Return:
 * NULL
 * address of the challenge buffer.
 */
unsigned char *smw_keymgr_get_attest_chal(struct smw_keymgr_attest_args *args);

/**
 * smw_keymgr_get_attest_chal_length() - Return the length of the challenge
 *                                       buffer.
 * @args: Pointer to the internal key attestation args structure.
 *
 * This function returns the length of the challenge buffer.
 *
 * Return:
 * 0
 * length of the challenge buffer.
 */
unsigned int
smw_keymgr_get_attest_chal_length(struct smw_keymgr_attest_args *args);

/**
 * smw_keymgr_get_attest_cert() - Return the address of the certificate buffer.
 * @args: Pointer to the internal key attestation args structure.
 *
 * This function returns the address of the certificate buffer.
 *
 * Return:
 * NULL
 * address of the certificate buffer.
 */
unsigned char *smw_keymgr_get_attest_cert(struct smw_keymgr_attest_args *args);

/**
 * smw_keymgr_get_attest_cert_length() - Return the length of the certificate
 *                                       buffer.
 * @args: Pointer to the internal key attestation args structure.
 *
 * This function returns the length of the certificate buffer.
 *
 * Return:
 * 0
 * length of the certificate buffer.
 */
unsigned int
smw_keymgr_get_attest_cert_length(struct smw_keymgr_attest_args *args);

/**
 * smw_keymgr_set_attest_cert_length() - Set the length of the certificate
 *                                       buffer.
 * @args: Pointer to the internal key attestation args structure.
 * @length: Length of the certificate buffer.
 *
 * This function sets the length of the certificate buffer.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_attest_cert_length(struct smw_keymgr_attest_args *args,
				       unsigned int length);

#endif /* __KEYMGR_ATTEST_H__ */
