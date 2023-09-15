/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __SMW_DEVICE_H__
#define __SMW_DEVICE_H__

#include <stdbool.h>

#include "smw_status.h"
#include "smw_strings.h"

/**
 * DOC:
 * The device APIs allow user of the library to:
 *  - Get information about the device.
 *  - Change the device lifecycle.
 */

/**
 * struct smw_device_attestation_args - Device attestation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @challenge: Caller unique ephemeral value (e.g. nonce)
 * @challenge_length: Length (in bytes) of the @challenge value
 * @certificate: Device attestation certificate.
 * @certificate_length: Length (in bytes) of the @certificate.
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
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
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @certificate: Device attestation certificate.
 * @certificate_length: Length (in bytes) of the @certificate.
 * @uuid: Device UUID buffer
 * @uuid_length: Length (in bytes) of the @uuid
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 *
 * Two methods are allowed to get the Device UUID.
 *
 * * Method #1
 *    Extract the device UUID from the device certificate.
 *    The Device Certificate (@certificate) is previously read using the
 *    smw_device_attestation() API.
 *
 * * Method #2
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
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @lifecycle_name: Device lifecycle name. See &typedef smw_lifecycle_t
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_device_lifecycle_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_lifecycle_t lifecycle_name;
};

/**
 * smw_device_attestation() - Get the device attestation certificate.
 * @args: Pointer to the structure that contains the device attestation arguments.
 *
 * Reads the device attestation certificate.
 *
 * Certificate length @args field is updated to the correct value when:
 *  - Length is bigger than expected. In this case operation succeeded.
 *  - Length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *  - Certificate buffer is set the NULL. In this case operation returned
 *    SMW_STATUS_OK
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_device_attestation(struct smw_device_attestation_args *args);

/**
 * smw_device_get_uuid() - Get the device UUID.
 * @args: Pointer to the structure that contains the device UUID arguments.
 *
 * Extracts device UUID from the device certificate or reads the device UUID
 * without device certificate.
 *
 * Device UUID buffer is in big endian format.
 *
 * UUID length @args field is updated to the correct value when:
 *  - Length is bigger than expected. In this case operation succeeded.
 *  - Length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *  - UUID buffer is set the NULL. In this case operation returned SMW_STATUS_OK
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_device_get_uuid(struct smw_device_uuid_args *args);

/**
 * smw_device_set_lifecycle() - Set the device to given lifecycle.
 * @args: Pointer to the structure that contains the device lifecycle arguments.
 *
 * Forward the device lifecycle to the given value. The device must be reset
 * to propagate the new lifecycle.
 *
 * **Caution:** Forwarding device lifecycle is not reversible.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_device_set_lifecycle(struct smw_device_lifecycle_args *args);

/**
 * smw_device_get_lifecycle() - Get the device active lifecycle.
 * @args: Pointer to the structure that contains the device lifecycle arguments.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_device_get_lifecycle(struct smw_device_lifecycle_args *args);

#endif /* __SMW_DEVICE_H__ */
