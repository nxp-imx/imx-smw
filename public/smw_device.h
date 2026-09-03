/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2026 NXP
 */

#ifndef __SMW_DEVICE_H__
#define __SMW_DEVICE_H__

#include <stdbool.h>

#include "smw_status.h"
#include "smw/names.h"

/**
 * typedef smw_soc_id_t - NXP SoC Identifiers
 *
 * List of all NXP SoC identifiers handled in the library.
 * List may be non-exhaustive.
 *
 * Values:
 *
 * * SOC_UNKNOWN: Device not identified.
 * * SOC_IMX8ULP: i.MX8ULP device.
 * * SOC_IMX91: i.MX91 device.
 * * SOC_IMX93: i.MX93 device.
 * * SOC_IMX95: i.MX95 device.
 * * SOC_IMX941: i.MX941 device.
 * * SOC_IMX942: i.MX942 device.
 * * SOC_IMX943: i.MX943 device.
 * * SOC_IMX937: i.MX937 device (equivalent to i.MX952).
 * * SOC_IMX952: i.MX952 device.
 */
typedef enum {
	SOC_UNKNOWN = 0x0,
	SOC_IMX8ULP = 0x84d,
	SOC_IMX91 = 0x9100,
	SOC_IMX93 = 0x9300,
	SOC_IMX95 = 0x9500,
	SOC_IMX941 = 0x9410,
	SOC_IMX942 = 0x9420,
	SOC_IMX943 = 0x9430,
	SOC_IMX937 = 0x9370,
	SOC_IMX952 = 0x9520,
} smw_soc_id_t;

/**
 * typedef smw_soc_revision_t - NXP SOC Revision
 *
 * List of revision handled in the library.
 * List may be non-exhaustive.
 *
 * Values:
 * * SOC_REV_A0: SoC revision A0.
 * * SOC_REV_A1: SoC revision A1.
 * * SOC_REV_A2: SoC revision A2.
 * * SOC_REV_B0: SoC revision B0.
 * * SOC_REV_B1: SoC revision B1.
 * * SOC_REV_C0: SoC revision C0.
 */
typedef enum {
	SOC_REV_A0 = 0xa000,
	SOC_REV_A1 = 0xa100,
	SOC_REV_A2 = 0xa200,
	SOC_REV_B0 = 0xb000,
	SOC_REV_B1 = 0xb100,
	SOC_REV_C0 = 0xc000,
} smw_soc_revision_t;

/**
 * struct smw_device_attestation_args - Device attestation arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @challenge: [in] Pointer to caller unique ephemeral value (e.g. nonce).
 * @challenge_length: [in] Length in bytes of the challenge buffer.
 * @certificate: [out] Pointer to the generated device attestation certificate.
 * @certificate_length: [in/out] Length in bytes of the certificate buffer.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 *
 * @challenge length depends of the device (refer to the subsystem capabilities).
 * If the length is bigger than expected, it will be cut to keep only the device
 * maximum size. If the length is shorter, the challenge value will be completed
 * with 0's.
 */
struct smw_device_attestation_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	unsigned char *challenge;
	unsigned int challenge_length;
	unsigned char *certificate;
	unsigned int certificate_length;
};

/**
 * struct smw_device_uuid_args - Device UUID arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @certificate: [in] Device attestation certificate.
 * @certificate_length: [in] Length in bytes of the certificate.
 * @uuid: [out] Device UUID buffer.
 * @uuid_length: [out] Length in bytes of the Device UUID buffer.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 *
 * Two methods are allowed to get the Device UUID:\
 *
 * - Method #1
 *    Extract the device UUID from the device certificate.
 *    The Device Certificate (@certificate) is previously read using the
 *    smw_device_attestation() API.
 *
 * - Method #2
 *    Read the device UUID without providing the Device Certificate. The
 *    field @certificate must be set to NULL.
 */
struct smw_device_uuid_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	unsigned char *certificate;
	unsigned int certificate_length;
	unsigned char *uuid;
	unsigned int uuid_length;
};

/**
 * struct smw_device_lifecycle_args - Device lifecycle arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @lifecycle_name:
 *  - [in] Name of the device lifecycle to set.
 *  - [out] Name of the current device lifecycle.
 *  - See &typedef smw_lifecycle_t.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 */
struct smw_device_lifecycle_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_lifecycle_t lifecycle_name;
};

/**
 * struct smw_device_reprovision_args - Device storage reprovisioning arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @data:
 *  - [in] Pointer to the data message signed sent to the device via the smw_device_reprovision().
 *  - [out] Pointer to the data message filled by the smw_device_reprovision_prepare().
 * @data_length:
 *  - [in] Length in bytes of the data buffer.
 *  - [out] Length in bytes of the data buffer generated by smw_device_reprovision_prepare().
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 */
struct smw_device_reprovision_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	unsigned char *data;
	unsigned int data_length;
};

/**
 * struct smw_device_info_args - Device information arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @soc_id: [out] SoC identifier. See &typedef smw_soc_id_t.
 * @soc_rev: [out] SoC revision. See &typedef smw_soc_revision_t.
 * @lifecycle: [out] SoC lifecycle. See &typedef smw_lifecycle_t.
 * @srkh_fused: [out] True if the OEM SRKH is fused, false otherwise.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 */
struct smw_device_info_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_soc_id_t soc_id;
	smw_soc_revision_t soc_rev;
	smw_lifecycle_t lifecycle;
	bool srkh_fused;
};

/**
 * smw_device_attestation() - Get the device attestation certificate.
 * @args: Pointer to the structure that contains the device attestation
 *        arguments.
 *
 * Reads the device attestation.
 *
 * To query the required certificate buffer length, set @args->certificate to
 * NULL. The function will then set the required certificate buffer length in
 * @args->certificate_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->certificate_length field is updated to
 * the correct value when:\
 *
 *  - Certificate buffer length is bigger than expected. In this case operation
 *    succeeds.
 *  - Certificate buffer length is shorter than expected. In this case operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - Additional invalid parameters returned by the subsystem.
 *  - SMW_STATUS_OPERATION_DISABLED:
 *      EL2GO provisioned keys are missing their Key Check Values (KCV) and the
 *      device attestation service is disabled.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_device_attestation(struct smw_device_attestation_args *args);

/**
 * smw_device_get_uuid() - Get the device UUID.
 * @args: Pointer to the structure that contains the device UUID arguments.
 *
 * Extracts device UUID from the device certificate, if @args->certificate
 * is set or reads the device UUID from device if @args->certificate is
 * NULL.
 *
 * Device UUID buffer is in big endian format.
 *
 * To query the required UUID buffer length, set @args->uuid to
 * NULL. The function will then set the required UUID buffer length in
 * @args->uuid_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->uuid_length field is updated to the
 * correct value when:\
 *
 *  - UUID buffer length is bigger than expected. In this case operation
 *    succeeds.
 *  - UUID buffer length is shorter than expected. In this case operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_device_get_uuid(struct smw_device_uuid_args *args);

/**
 * smw_device_set_lifecycle() - Set the device to given lifecycle.
 * @args: Pointer to the structure that contains the device lifecycle arguments.
 *
 * Forward the device lifecycle to the given value. The device must be reset
 * to propagate the new lifecycle.
 *
 * .. warning::
 *   Forwarding device lifecycle is not reversible.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_device_set_lifecycle(struct smw_device_lifecycle_args *args);

/**
 * smw_device_get_lifecycle() - Get the device active lifecycle.
 * @args: Pointer to the structure that contains the device lifecycle arguments.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_device_get_lifecycle(struct smw_device_lifecycle_args *args);

/**
 * smw_device_reprovision_prepare() - Fill the device reprovisioning message.
 * @args: Pointer to the structure that contains the reprovisioning arguments.
 *
 * This function is used to fill the reprovisioning message that will have to
 * be signed by the user using the device keys.
 *
 * .. warning::
 *   This function is only available for the ELE (EdgeLock Enclave)
 *   Secure Subsystem.
 *
 * To query the required data buffer length, set @args->data to
 * NULL. The function will then set the required data buffer length in
 * @args->data_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->data_length field is updated to the
 * correct value when:\
 *
 *  - Data buffer length is bigger than expected. In this case operation
 *    succeeds.
 *  - Data buffer length is shorter than expected. In this case operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_device_reprovision_prepare(struct smw_device_reprovision_args *args);

/**
 * smw_device_reprovision() - Request device storage reprovisioning.
 * @args: Pointer to the structure that contains the reprovisioning arguments.
 *
 * This function is used to request the subsystem to enable the secure storage
 * re-provisioning. In this case, the rollback protection of the storage is
 * reset and consequently all objects previously stored are lost.
 *
 * .. warning::
 *   This function is only available for the ELE (EdgeLock Enclave)
 *   Secure Subsystem.
 *
 * The field data of @args->data might contain the ELE reprovisioning signed
 * message to be passed to the ELE Secure Subsystem.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->data is NULL.
 *      - @args->data_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_device_reprovision(struct smw_device_reprovision_args *args);

/**
 * smw_device_get_info() - Get the device information.
 * @args: Pointer to the structure that contains the device information
 *        arguments.
 *
 * Reads the device information including the SoC ID, SoC revision and
 * whether the OEM SRKH is fused.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_device_get_info(struct smw_device_info_args *args);

#endif /* __SMW_DEVICE_H__ */
