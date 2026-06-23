/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __LOCAL_H__
#define __LOCAL_H__

#include "common.h"
#include "utils.h"
#include "utils_ex.h"
#include "math.h"

#include <prime.h>

/*
 * ELA hardware requires 64-byte alignment for i/p and o/p buffers
 */
#define ELA_BUFFER_ALIGN_SIZE 64

/* FCE status codes */
#define FCE_STATUS_SUCCESS 0xD6
#define FCE_STATUS_ERROR   0x29

/* FCE error_info values (when status_code == FCE_STATUS_ERROR) */
/* Unknown MU Command received by FCE parser */
#define FCE_ERR_INVALID_MESSAGE 0x00

/* MU Command recognized but not yet implemented */
#define FCE_ERR_NOT_IMPLEMENTED 0x02

/* FCE request ID in the MU buffer is invalid */
#define FCE_ERR_INVALID_REQ_ID 0x03

/* FCE request was accepted but execution failed */
#define FCE_ERR_FCE_REQ_ERROR 0x12

/* Payload size is not correctly aligned to required boundary */
#define FCE_ERR_PAYLOAD_SIZE 0x13

/* FCE Service Open API called when service is already open */
#define FCE_ERR_SERVICE_ALREADY_OPENED 0x15

/* Requested TAG size is not supported by the FCE hardware */
#define FCE_ERR_TAG_SIZE 0x16

/* FCE failed to write the computed digest into SoC memory */
#define FCE_ERR_PFWR_DIGEST 0x17

/* FCE internal request FIFO is full, no more requests can be pushed */
#define FCE_ERR_FIFO_FULL 0x20

/* No key slots were set in the Push Command */
#define FCE_ERR_NO_SLOTS 0x30

/* Requested key slot number exceeds the allowed range */
#define FCE_ERR_KEY_SLOT_OUT_OF_RANGE 0x40

/* Key size provided is not valid for the requested algorithm */
#define FCE_ERR_KEY_SIZE_INVALID 0x41

/* Algorithm specified in the request is not supported by FCE */
#define FCE_ERR_INVALID_ALGO 0x50

/* HMAC or authentication tag verification failed */
#define FCE_ERR_VERIFICATION_FAILED 0x60

/**
 * struct ela_context - ELA service context
 * @service_hdl: Prime service handle
 * @virtual_addr: Virtual address of memory buffer
 * @physical_addr: Physical address of memory buffer
 * @memory_size: Size of memory buffer
 * @mutex: Mutex for thread safety
 */
struct ela_context {
	prime_hdl_t service_hdl;
	void *virtual_addr;
	uint64_t physical_addr;
	uint32_t memory_size;
	void *mutex;
};

/**
 * convert_fce_status() - Convert FCE status to SMW status
 * @status_code: FCE status code
 * @error_info: FCE error info
 *
 * Return:
 * SMW status code
 */
int convert_fce_status(uint8_t status_code, uint8_t error_info);

/**
 * ela_get_context() - Get ELA context
 *
 * Return:
 * Pointer to ELA context
 */
struct ela_context *ela_get_context(void);

/**
 * convert_ela_err() - Convert Prime error to SMW status
 * @err: Prime error code
 *
 * Return:
 * SMW status code
 */
int convert_ela_err(prime_err_t err);

/**
 * ela_cipher_handle() - Handle the cipher encryption/decryption operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the cipher encryption/decryption operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ela_cipher_handle(enum operation_id operation_id, void *args, int *status);

/**
 * ela_open_service() - Open ELA service with specified memory size
 * @size: Required memory size for ELA operations
 *
 * This function opens the PRIME service session if not already open and
 * allocates a shared buffer of @size.
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY - Subsystem memory allocation failure.
 */
int ela_open_service(uint32_t size);

/**
 * ela_close_service() - Close ELA service
 *
 * Closes the PRIME service session.
 *
 * Return:
 * None
 */
void ela_close_service(void);

/**
 * ela_load_aes_key() - Load AES key into ELA key slot
 * @service_hdl: ELA service handle
 * @key_desc: Key descriptor containing the key material
 * @keyslot: Pointer to store the allocated key slot number
 *
 * Return:
 * SMW_STATUS_OK - Success
 * SMW_STATUS_INVALID_PARAM - Invalid parameters
 * Error code otherwise
 */
int ela_load_aes_key(prime_hdl_t service_hdl,
		     struct smw_keymgr_descriptor *key_desc, uint8_t *keyslot);

#endif /* __LOCAL_H__ */
