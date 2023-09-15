/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __DEVMGR_H___
#define __DEVMGR_H___

#include "smw_device.h"

enum smw_op_devmgr {
	SMW_OP_DEVMGR_ATTESTATION,
	SMW_OP_DEVMGR_UUID,
	SMW_OP_DEVMGR_SET_LIFECYCLE,
	SMW_OP_DEVMGR_GET_LIFECYCLE
};

/**
 * struct smw_devmgr_args - Device manager arguments
 * @op: Device manager operation
 * @pub: Pointer to the public API arguments structure
 *
 */
struct smw_devmgr_args {
	enum smw_op_devmgr op;
	union {
		struct smw_device_attestation_args *attestation;
		struct smw_device_uuid_args *uuid;
	} pub;
};

/**
 * struct smw_devmgr_lifecycle_args - Device lifecycle arguments
 * @lifecycle_id: Internal device lifecycle value
 */
struct smw_devmgr_lifecycle_args {
	enum smw_op_devmgr op;
	unsigned int lifecycle_id;
};

/**
 * smw_devmgr_get_challenge_data() - Return the address of the challenge
 *                                   buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the address of the challenge buffer.
 *
 * Return:
 * NULL
 * address of the challenge buffer
 */
unsigned char *smw_devmgr_get_challenge_data(struct smw_devmgr_args *args);

/**
 * smw_devmgr_get_challenge_length() - Return the length of the challenge
 *                                     buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the length of the challenge buffer.
 *
 * Return:
 * 0
 * length of the challenge buffer.
 */
unsigned int smw_devmgr_get_challenge_length(struct smw_devmgr_args *args);

/**
 * smw_devmgr_get_certificate_data() - Return the address of the certificate
 *                                     buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the address of the certificate buffer.
 *
 * Return:
 * NULL
 * address of the certificate buffer
 */
unsigned char *smw_devmgr_get_certificate_data(struct smw_devmgr_args *args);

/**
 * smw_devmgr_get_certificate_length() - Return the length of the certificate
 *                                       buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the length of the certificate buffer.
 *
 * Return:
 * 0
 * length of the certificate buffer.
 */
unsigned int smw_devmgr_get_certificate_length(struct smw_devmgr_args *args);

/**
 * smw_devmgr_set_certificate_length() - Set the length of the certificate
 *                                       buffer.
 * @args: Pointer to the internal device args structure.
 * @length: Length of the certificate buffer.
 *
 * This function sets the length of the certificate buffer.
 *
 * Return:
 * none.
 */
void smw_devmgr_set_certificate_length(struct smw_devmgr_args *args,
				       unsigned int length);

/**
 * smw_devmgr_get_uuid_data() - Return the address of the device UUID buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the address of the device UUID buffer.
 *
 * Return:
 * NULL
 * address of the device UUID buffer
 */
unsigned char *smw_devmgr_get_uuid_data(struct smw_devmgr_args *args);

/**
 * smw_devmgr_get_uuid_length() - Return the length of the device UUID buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the length of the device UUID buffer.
 *
 * Return:
 * 0
 * length of the device UUID buffer.
 */
unsigned int smw_devmgr_get_uuid_length(struct smw_devmgr_args *args);

/**
 * smw_devmgr_set_uuid_length() - Set the length of the device UUID buffer.
 * @args: Pointer to the internal device args structure.
 * @length: Length of the device UUID buffer.
 *
 * This function sets the length of the device UUID buffer.
 *
 * Return:
 * none.
 */
void smw_devmgr_set_uuid_length(struct smw_devmgr_args *args,
				unsigned int length);
#endif /* __DEVMGR_H___ */
