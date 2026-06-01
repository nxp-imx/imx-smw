/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __ELE_CRYPTO_MAC_H__
#define __ELE_CRYPTO_MAC_H__

#include "ele_crypto_key_mgr.h"
#include "ele_crypto_hash.h"

/*******************************************************************************
 * MAC Definitions
 ******************************************************************************/

/* Verification status values returned by ELE_Mac() in MAC_VERIFY mode */
#define MAC_VERIFY_SUCCESS (0x6c1aa1c6u) /* MAC Verification success */

/**
 * mac_mode_t - MAC mode
 * MAC_VERIFY: MAC is generated in ELE local memory and compared with MAC at MAC address
 * MAC_GENERATE: MAC is generated and copied at the MAC address
 * MAC_USE_PLAIN_KEY_BUFFER: MAC is generated using the key provided in the key buffer
 */
typedef enum {
	MAC_VERIFY = 0x0u,
	MAC_GENERATE = 0x1u,
	MAC_USE_PLAIN_KEY_BUFFER = 0x8u,
} mac_mode_t;

/**
 * ele_mac_t - ELE MAC structure.
 * @mac_handle_id: Unique Cipher handle ID obtained by calling ELE_OpenMacService()
 * @key_id: Key ID obtained by calling ELE_GenerateKey()
 * @payload: Pointer where payload data can be found
 * @payload_size: Size of payload data in bytes
 * @mac: Pointer to MAC data
 * @mac_size: Size of MAC data in bytes
 * @alg: Algorithm identifier. Refer to key_permitted_alg_t enum.
 * @mode: Mode identifier. Refer to mac_mode_t enum.
 */
typedef struct {
	uint32_t mac_handle_id;
	uint32_t key_id;
	uint8_t *key;
	uint8_t *payload;
	uint32_t payload_size;
	uint8_t *mac;
	uint16_t mac_size;
	key_permitted_alg_t alg;
	mac_mode_t mode;
	uint16_t key_size;
	uint16_t key_type;
} ele_mac_t;

/*
 * FastMAC-specific definitions for the 'Fast MAC Proceed' command
 * flags to be OR'd together as per the user's needs. See FastMAC documentation
 * for specifics.
 */

/* Preload msg buffer 0. */
#define FAST_MAC_PRELOAD_BUFF_0 (0x00000001u)
/* Preload msg buffer 1. */
#define FAST_MAC_PRELOAD_BUFF_1 (0x00000002u)
/* Preload msg buffer 2. */
#define FAST_MAC_PRELOAD_BUFF_2 (0x00000004u)
/* Preload msg buffer 3. */
#define FAST_MAC_PRELOAD_BUFF_3 (0x00000008u)

/* HMAC proceed over msg buffer 0. */
#define FAST_MAC_PROCEED_BUFF_0 (0x00000010u)
/* HMAC proceed over msg buffer 1. */
#define FAST_MAC_PROCEED_BUFF_1 (0x00000020u)
/* HMAC proceed over msg buffer 2. */
#define FAST_MAC_PROCEED_BUFF_2 (0x00000040u)
/* HMAC proceed over msg buffer 3. */
#define FAST_MAC_PROCEED_BUFF_3 (0x00000080u)
/* HMAC proceed all four buffers. */
#define FAST_MAC_PROCEED_ALL_BUFF                                              \
	(FAST_MAC_PROCEED_BUFF_0 | FAST_MAC_PROCEED_BUFF_1 |                   \
	 FAST_MAC_PROCEED_BUFF_2 | FAST_MAC_PROCEED_BUFF_3)

/*
 * Verify internally. When this flag is set while also utilizing preloading,
 * ELE assumes that Message address field is a concatenation of message and expected HMAC.
 * Message = (message || expected_HMAC). At the end of the HMAC computation,
 * ELE will compare expteced_HMAC with the calculated HMAC and report the status.
 * In this scenario, message size API input must be size of message + size of expected HMAC
 * in bytes.
 */
#define FAST_MAC_VERIFY_INTERNALLY (0x00000100u)

/*
 * One shot mode. One shot: Do not use preload mechanism. When this flag is set,
 * Message field is the message, and MAC field is the output buffer or expected
 * HMAC buffer depending on verify internally flag
 */
#define FAST_MAC_ONE_SHOT (0x00000200u)

/* Use key 0 for the specified message. */
#define FAST_MAC_USE_KEY_0 (0x00000000u)
/* Use key 1 for the specified message. */
#define FAST_MAC_USE_KEY_1 (0x00000400u)

/* HMAC trunctation to 8 Bytes. */
#define FAST_MAC_TRUNCATE_08B (0x00000800u)
/* HMAC trunctation to 16 Bytes. */
#define FAST_MAC_TRUNCATE_16B (0x00001000u)
/* HMAC trunctation to 24 Bytes. */
#define FAST_MAC_TRUNCATE_24B (0x00001800u)
/* HMAC trunctation to 32 Bytes (no truncation done). */
#define FAST_MAC_TRUNCATE_32B (0x00003800u)

/*
 * Check buffer 0 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification success.
 */
#define FAST_MAC_CHECK_VERIFICATION_SUCCESS_BUF_0(x) (((uint32_t)x) & 0x01)
/*
 * Check buffer 1 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification success.
 */
#define FAST_MAC_CHECK_VERIFICATION_SUCCESS_BUF_1(x)                           \
	((((uint32_t)x) & 0x02) >> 1)
/*
 * Check buffer 2 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification success.
 */
#define FAST_MAC_CHECK_VERIFICATION_SUCCESS_BUF_2(x)                           \
	((((uint32_t)x) & 0x04) >> 2)
/*
 * Check buffer 3 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification success.
 */
#define FAST_MAC_CHECK_VERIFICATION_SUCCESS_BUF_3(x)                           \
	((((uint32_t)x) & 0x08) >> 3)
/*
 * Check oneshot internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification success.
 */
#define FAST_MAC_CHECK_VERIFICATION_SUCCESS_ONESHOT(x)                         \
	((((uint32_t)x) & 0x80) >> 7)

/*
 * Check buffer 0 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification failure.
 */
#define FAST_MAC_CHECK_VERIFICATION_FAILURE_BUF_0(x)                           \
	((((uint32_t)x) & 0x100) >> 8)
/*
 * Check buffer 1 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification failure.
 */
#define FAST_MAC_CHECK_VERIFICATION_FAILURE_BUF_1(x)                           \
	((((uint32_t)x) & 0x200) >> 9)
/*
 * Check buffer 2 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification failure.
 */
#define FAST_MAC_CHECK_VERIFICATION_FAILURE_BUF_2(x)                           \
	((((uint32_t)x) & 0x400) >> 10)
/*
 * Check buffer 3 internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification failure.
 */
#define FAST_MAC_CHECK_VERIFICATION_FAILURE_BUF_3(x)                           \
	((((uint32_t)x) & 0x800) >> 11)
/*
 * Check oneshot internal verification status returned by ELE_FastMacProceed().
 * Returns 1 if verification failure.
 */
#define FAST_MAC_CHECK_VERIFICATION_FAILURE_ONESHOT(x)                         \
	((((uint32_t)x) & 0x8000) >> 15)

/*******************************************************************************
 * API
 *******************************************************************************/

/**
 * ele_open_mac_service() - Open ELE MAC Service
 * @mu: MU peripheral base address
 * @keystore_handle_id: unique session ID obtained by calling ELE_OpenKeystore()
 * @mac_handle_id: pointer to output unique MAC session handle ID word
 *
 * This function opens MAC Service for EdgeLock Enclave.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_open_mac_service(s3mu_t *mu, uint32_t keystore_handle_id,
			      uint32_t *mac_handle_id);

/**
 * ele_close_mac_service() - Close ELE MAC Service
 * @mu: MU peripheral base address
 * @mac_handle_id: unique MAC handle ID obtained by calling ele_open_mac_service()
 *
 * This function closes the MAC Service for EdgeLock Enclave.
 *
 * Return:
 * STATUS_SUCCESS - Success
 * STATUS_FAIL    - Fail
 */
status_t ele_close_mac_service(s3mu_t *mu, uint32_t mac_handle_id);

/**
 * ele_mac() - ELE MAC
 * @mu: MU peripheral base address
 * @conf: pointer where the MAC configuration structure can be found
 * @out_mac_size: pointer where to save the size, in bytes,
 *                of the resulting MAC in MAC_GENERATE mode,
 *                or the input MAC size in MAC_VERIFY mode.
 *
 * This function is used to perform one-shot MAC generation or verification.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_INVALID_ARGUMENT          - Invalid argument
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 * STATUS_ELE_BUFFER_TOO_SMALL       - Buffer too small
 */
status_t ele_mac(s3mu_t *mu, ele_mac_t *conf, uint16_t *out_mac_size);

/**
 * ele_fast_mac_start() - Fast Mac Start
 * @mu: MU peripheral base address
 * @key: Pointer to key data buffer, which is expected to be 64 Bytes long
 *       consisting of two 256 bit keys.
 *       The key size is hardcoded to 256 bits and other key sizes are not supported.
 *
 * This command is used to enter in "Fast MAC" operation mode.
 * This is the first step of the fast MAC API.
 * During this step, ELE will copy key into internal memory in order to accelerate
 * future usage of the key.
 * ELE will also enter in a special mode where only Fast MAC will be accepted.
 * All other commands will be rejected.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_fast_mac_start(s3mu_t *mu, const uint8_t *key);

/**
 * ele_fast_mac_proceed() - Fast Mac Proceed
 * @mu: MU peripheral base address
 * @msg: pointer where input message data can be found
 * @mac: pointer to a buffer where the MAC data are written by ELE.
 *       If doing a OneShot operation with internal verification enabled,
 *       this buffer must hold the expected MAC value.
 * @msg_size: size of message in bytes. If doing a Preload operation with
 *            internal verification enabled, this must be the length of the
 *            input message + the length of the concatenated expected MAC.
 *            note: If oneshot, limit is UIN16_MAX, otherwise 512 Bytes.
 * @flags: the flags specifying Fast MAC Proceed behavior.
 *         See the FAST_MAC_* macros.
 * @verif_status: returns the verification status after MAC computation if
 *                the internal verification flag was enabled. May be NULL.
 *                See the FAST_MAC_CHECK_VERIFICATION_* macros for
 *                checking the returned status.
 *
 * This command is used to proceed with a Fast MAC generation.
 * The user gives as input the message buffer and size,
 * and ELE output to the User's MAC buffer the computed MAC.
 * ELE use the key given in Start API.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_fast_mac_proceed(s3mu_t *mu, const uint8_t *msg, uint8_t *mac,
			      uint16_t msg_size, uint16_t flags,
			      uint32_t *verif_status);

/**
 * ele_fast_mac_end() - Fast Mac End
 * @mu: MU peripheral base address
 *
 * This command is used to exit from "Fast MAC" mode.
 *
 * Return:
 * STATUS_SUCCESS                  - Success
 * STATUS_FAIL                     - Fail
 * STATUS_S3MU_INVALID_ARGUMENT     - Invalid argument parameter
 * STATUS_S3MU_ARGUMENT_OUT_OF_RANGE   - Argument out of range
 */
status_t ele_fast_mac_end(s3mu_t *mu);

#endif /* __ELE_CRYPTO_MAC_H__ */
