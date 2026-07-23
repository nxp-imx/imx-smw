/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024, 2026 NXP
 */

#ifndef __DEVMGR_H___
#define __DEVMGR_H___

#include "smw_device.h"
#include "lifecycle.h"

enum smw_op_devmgr {
	SMW_OP_DEVMGR_ATTESTATION,
	SMW_OP_DEVMGR_UUID,
	SMW_OP_DEVMGR_SET_LIFECYCLE,
	SMW_OP_DEVMGR_GET_LIFECYCLE,
	SMW_OP_DEVMGR_REPROVISION_PREP,
	SMW_OP_DEVMGR_REPROVISION,
	SMW_OP_DEVMGR_GET_INFO
};

/**
 * struct smw_devmgr_args - Device manager arguments
 * @op: Device manager operation
 * @pub: Union of pointers to the public API arguments structure
 * @pub.attestation: Pointer to the device attestation arguments
 * @pub.uuid: Pointer to the device UUID arguments
 * @pub.reprovision: Pointer to the device storage reprovisioning arguments
 * @pub.info: Pointer to the device information arguments
 */
struct smw_devmgr_args {
	enum smw_op_devmgr op;
	union {
		struct smw_device_attestation_args *attestation;
		struct smw_device_uuid_args *uuid;
		struct smw_device_reprovision_args *reprovision;
		struct smw_device_info_args *info;
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

/**
 * smw_devmgr_get_reprovisioning_data() - Return the address of the
 *                                        reprovisioning buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the address of the device storage reprovisioning
 * buffer.
 *
 * Return:
 * NULL
 * address of the device reprovisioning buffer
 */
unsigned char *smw_devmgr_get_reprovision_data(struct smw_devmgr_args *args);

/**
 * smw_devmgr_get_reprovisiong_length() - Return the length of the device
 *                                        reprovisioning buffer.
 * @args: Pointer to the internal device args structure.
 *
 * This function returns the length of the device storage reprovisioning buffer.
 *
 * Return:
 * 0
 * length of the device reprovisioning buffer.
 */
unsigned int smw_devmgr_get_reprovision_length(struct smw_devmgr_args *args);

/**
 * smw_devmgr_set_reprovisiong_length() - Set the length of the device
 *                                        reprovisioning buffer.
 * @args: Pointer to the internal device args structure.
 * @length: Length of the reprovisioning buffer.
 *
 * This function sets the length of the device storage reprovisioning buffer.
 *
 * Return:
 * None.
 */
void smw_devmgr_set_reprovision_length(struct smw_devmgr_args *args,
				       unsigned int length);

/**
 * smw_devmgr_set_device_soc() - Set the device information SoC ID and revision.
 * @args: Pointer to the internal device args structure.
 * @soc_id: SoC identifier.
 * @soc_rev: SoC revision.
 *
 * This function fills the public device info args structure with the
 * device id and revision.
 *
 * Return:
 * None.
 */
void smw_devmgr_set_device_soc(struct smw_devmgr_args *args,
			       smw_soc_id_t soc_id, smw_soc_revision_t soc_rev);

/**
 * smw_devmgr_set_device_srkh() - Set the device information SRKH status.
 * @args: Pointer to the internal device args structure.
 * @srkh_fused: True if the OEM SRKH is fused.
 *
 * This function fills the public device info args structure if SRKH is
 * fused or not.
 *
 * Return:
 * None.
 */
void smw_devmgr_set_device_srkh(struct smw_devmgr_args *args, bool srkh_fused);

/**
 * smw_devmgr_set_device_lifecycle() - Set the device information lifecycle.
 * @args: Pointer to the internal device args structure.
 * @id: Lifecycle value.
 *
 * This function fills the public device info args structure with the
 * lifecycle.
 *
 * Return:
 * None.
 */
void smw_devmgr_set_device_lifecycle(struct smw_devmgr_args *args,
				     enum smw_lifecycle_id id);
#endif /* __DEVMGR_H___ */
