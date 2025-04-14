/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __SMW_OEM_MASTER_KEY__
#define __SMW_OEM_MASTER_KEY__

/**
 * struct smw_kdf_oem_master_key_args - OEM Master key derivation arguments
 * @version: [in] Version of this structure.
 * @op: [in] OEM Master key derivation operation.
 *      See &typedef smw_oem_master_key_op_t
 * @use_peer_key_digest_kdf: [in] True if the peer key digest value is used
 *                                as salt to derive the OEM Master key.
 * @use_oem_srkh_kdf: [in] True if the OEM SRKH is used as salt to derive
 *                         OEM wrapping and signing keys.
 * @peer_public_buffer: [in] Key derivation input data used to generate the
 *                      shared secret key
 * @peer_public_buffer_length: [in] Length in bytes of the @peer_public_buffer
 *                             buffer
 * @info: [in] [optional] Context and application specific information
 * @info_len: [in] @info length in bytes
 * @payload: [in/out] Depends on the operation type defined by @op
 * @payload_length: [in/out] Length of the @payload buffer.
 *
 * OEM Master key derivation operation is not supported on all subsystems,
 * refer to the Subsystems Capabilities.
 *
 * This key is used to import keys in the Secure Storage using a blob
 * transporting the key in a secure manner.
 * The blob is a TLV encoded message in which the key is encrypted and blob
 * is signed. The encryption of the key uses a key derived from the OEM
 * Master key and the blob signature uses a key derived from the OEM Master
 * key. More details are available in the Subsystems Capabilities.
 *
 * This structure contains the information required to:
 * * Either prepare the payload data that must be signed.
 * * Or derive the OEM Master key that will be used to import a key in the
 *   Secure Enclave.
 *
 * This arguments structure is the @kdf_arguments of the
 * &struct smw_derive_key_args where @kdf_name is set to
 * `SMW_KDF_NAME_OEM_MASTER_KEY`
 *
 * All &struct smw_derive_key_args fields may not be used for this operation
 * and if set may be overwritten with hardcoded value as described in the
 * subsystem capabilities.
 *
 * The supported operations (@op) are:
 *  - Prepare the OEM Master key payload to sign:
 *    The @payload is an output, it's built based on the user parameters
 *    given for the operation.
 *    This payload must be signed to attest the derive operation.
 *    It's an optional functionality proposed to facilitate the user process.
 *    Other NXP tool, like `SPSDK <https://spsdk.readthedocs.io/en/latest/index.html>`_
 *    can be used to build and sign the payload.
 *    Calling this operation with `@payload = NULL` will return the expected
 *    length of the payload buffer in the @payload_length.
 *
 *  - Derive the OEM Master key:
 *    The @payload is an input. It must be a payload signed.
 *
 */
struct smw_kdf_oem_master_key_args {
	unsigned char version;
	smw_oem_master_key_op_t op;
	bool use_peer_key_digest_kdf;
	bool use_oem_srkh_kdf;
	unsigned char *peer_public_buffer;
	unsigned int peer_public_buffer_length;
	unsigned char *info;
	unsigned int info_len;
	unsigned char *payload;
	unsigned int payload_length;
};

#endif /* __SMW_OEM_MASTER_KEY__ */
