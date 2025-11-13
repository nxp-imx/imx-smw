/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2025 NXP
 */

#ifndef __LIB_DEVICE_H__
#define __LIB_DEVICE_H__

#include "types.h"

/**
 * libdev_get_slotdev() - Get the slot's device object
 * @dev: Reference to the device object to set
 * @slotid: Slot ID
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_OK                        - Success
 */
CK_RV libdev_get_slotdev(struct libdevice **dev, CK_SLOT_ID slotid);

/**
 * libdev_get_slotinfo() - Get the slot information
 * @slotid: Slot ID
 * @pinfo : Slot Information output structure
 *
 * Function copy the @slotid slot information into the @pinfo structure
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_OK                        - Success
 */
CK_RV libdev_get_slotinfo(CK_SLOT_ID slotid, CK_SLOT_INFO_PTR pinfo);

/**
 * libdev_get_tokeninfo() - Get the token information
 * @slotid: Slot ID
 * @pinfo : Token Information output structure
 *
 * Function copy the @slotid token information into the @pinfo structure
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No token defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_FUNCTION_FAILED           - Failure
 * CKR_OK                        - Success
 */
CK_RV libdev_get_tokeninfo(CK_SLOT_ID slotid, CK_TOKEN_INFO_PTR pinfo);

/**
 * libdev_get_slots() - Return the list of slots
 * @nb_solts: Number of slots
 * @slotlist: List of slots
 * @tokenPresent: Whether or not a token is present
 *
 * Return the number of slots in @nb_solts and if @slotlist not
 * NULL, fill the list of slots, retricted to the slots with a token
 * present if @tokenPresent is TRUE.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_BUFFER_TOO_SMALL          - Pointer to the list buffer too small
 * CKR_OK                        - Success
 *
 */
CK_RV libdev_get_slots(CK_ULONG_PTR nb_solts, CK_SLOT_ID_PTR slotlist,
		       CK_BBOOL tokenPresent);

/**
 * libdev_init_token() - Initialize a token
 * @slotid: Slot ID
 * @label: Application label
 *
 * Initialize a token if present and if there is no session opened on this
 * token.
 * If the token is already initialized (and no session opened), re-initialied
 * the token (destroyed all non_permanent objects associated to the token).
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT         - Token is not present
 * CKR_OK                        - Success
 */
CK_RV libdev_init_token(CK_SLOT_ID slotid, CK_UTF8CHAR_PTR label);

/**
 * libdev_initialize() - Initialize the library context devices
 * @devices: Library devices context
 *
 * Allocate the devices' context and initialized it.
 *
 * Return:
 * CKR_GENERAL_ERROR - No context available
 * CKR_HOST_MEMORY   - Out of memory
 * CKR_OK            - Success
 */
CK_RV libdev_initialize(struct libdevice **devices);

/**
 * libdev_destroy() - Destroy the library context devices
 * @devices: Library devices context
 *
 * Free all the devices' context.
 *
 * Return:
 * CKR_GENERAL_ERROR - No context available
 * CKR_HOST_MEMORY   - Out of memory
 * CKR_OK            - Success
 */
CK_RV libdev_destroy(struct libdevice **devices);

/**
 * libdev_get_devinfo() - Return a reference to @slotid's device information
 * @slotid: Slot ID
 *
 * Return: Reference to the device information list
 */
const struct libdev *libdev_get_devinfo(CK_SLOT_ID slotid);

/**
 * libdev_get_nb_devinfo() - Return the number of device information
 *
 * Return: Number of device information
 */
unsigned int libdev_get_nb_devinfo(void);

/**
 * libdev_slot_valid() - Return if the @slotid is valid or not
 * @slotid: Slot ID
 *
 * Return: True if valid, false otherwise
 */
static inline bool libdev_slot_valid(CK_SLOT_ID slotid)
{
	unsigned int nb_devices;

	nb_devices = libdev_get_nb_devinfo();

	return (slotid < nb_devices);
}

/**
 * libdev_set_present() - Update the Device slot flag presence status
 * @devices: Reference to the library devices
 */
void libdev_set_present(struct libdevice *devices);

/**
 * libdev_get_mechanisms() - Return the list of Slot ID's mechanisms
 * @slotid: Slot ID
 * @mechanismlist: Application reference to the list of mechanisms to fill
 * @count: Reference to the number of Slot ID's mechanisms
 *
 * Return the number of mechanisms supported by the @slotid and if
 * the @mechanismlist not NULL, full the list with the mechanisms' IDs.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_BUFFER_TOO_SMALL          - Pointer to the list buffer too small
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT         - Token is not present
 * CKR_OK                        - Success
 */
CK_RV libdev_get_mechanisms(CK_SLOT_ID slotid,
			    CK_MECHANISM_TYPE_PTR mechanismlist,
			    CK_ULONG_PTR count);

/**
 * libdev_get_mechanism_info() - Return the information on @slotid's mechanism
 * @slotid: Slot ID
 * @type: Mechanisms type
 * @info: Application reference to the mechanism information
 * @op_flag: Operation flag to validate mechanism against
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT         - Token is not present
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_OK                        - Success
 */
CK_RV libdev_get_mechanism_info(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				CK_MECHANISM_INFO_PTR info, CK_FLAGS op_flag);

/**
 * libdev_validate_mechanism() - Validate mechanism
 * @slotid: Slot ID
 * @mech: Mechanism definition
 * @op_flag: Operation flag
 *
 * Checks if a slot ID is supporting given mechanism and
 * if mechanism applies to operation
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT         - Token is not present
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_OK                        - Success
 */
CK_RV libdev_validate_mechanism(CK_SLOT_ID slotid, CK_MECHANISM_PTR mech,
				CK_FLAGS op_flag);

/**
 * libdev_operate_mechanism() - Operate the mechanism calling SMW APIs
 * @hsession: Session handle
 * @mech: Mechanism definition
 * @args: SMW API arguments
 * @op_flag: Operation flag
 *
 * Function prepare the SMW API argument for the API operation.
 * Other arguments might be set function of the mechanism operation.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_FUNCTION_CANCELED         - Application callback canceled function
 * CKR_BUFFER_TOO_SMALL          - Output buffer too small
 * CKR_SIGNATURE_INVALID         - Signature is invalid
 * CKR_SIGNATURE_LEN_RANGE       - Signature length is invalid
 * CKR_OK                        - Success
 */
CK_RV libdev_operate_mechanism(CK_SESSION_HANDLE hsession,
			       CK_MECHANISM_PTR mech, void *args,
			       CK_FLAGS op_flag);

/**
 * libdev_import_key() - Call SMW import key API
 * @hsession: Session handle
 * @obj: Key object to import
 *
 * Function prepare the SMW API argument for the API key import.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute type is not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libdev_import_key(CK_SESSION_HANDLE hsession, struct libobj_obj *obj);

/**
 * libdev_get_key_attributes() - Call SMW get attribute key API
 * @hsession: Session handle
 * @obj: Key object to export
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute type is not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libdev_get_key_attributes(CK_SESSION_HANDLE hsession,
				struct libobj_obj *obj);

/**
 * libdev_export_public_key() - Call SMW export key API
 * @obj: Key object to export
 *
 * Return:
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libdev_export_public_key(const struct libobj_obj *obj);

/**
 * libdev_delete_key() - Call SMW delete key API
 * @key_id: Key id to deleete
 *
 * Function build the SMW API argument to delete a key in the session's
 * subsystem.
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Key id is 0
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libdev_delete_key(unsigned int key_id);

/**
 * libdev_mechanisms_init() - Initialize the device mechanism information
 * @slotid: Slot ID
 *
 * Return:
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_OK                        - Success
 */
CK_RV libdev_mechanisms_init(CK_SLOT_ID slotid);

/**
 * libdev_rng() - Call SMW random number generator API
 * @hsession: Session handle
 * @pRandomData: Location that receives the random data
 * @ulRandomLen: Length in bytes of the random data
 *
 * Function build the SMW API argument to generate a random number.
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Bad arguments
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libdev_rng(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pRandomData,
		 CK_ULONG ulRandomLen);

/**
 * libdev_create_data() - Create new SMW data
 * @hsession: Session handle
 * @obj: Data object
 *
 * Function calls the SMW API to create a new library data if data label
 * is supported.
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Bad arguments
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV libdev_create_data(CK_SESSION_HANDLE hsession, struct libobj_obj *obj);

/**
 * libdev_get_data_attributes() - Get the SMW data attributes
 * @obj: Data object
 *
 * Function calls the SMW API to get the data attributes.
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Bad arguments
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV libdev_get_data_attributes(struct libobj_obj *obj);

/**
 * libdev_get_data_value() - Get the SMW data value
 * @obj: Data object
 *
 * Function calls the SMW API to get data value.
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Bad arguments
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV libdev_get_data_value(const struct libobj_obj *obj);

/**
 * libdev_delete_data() - Delete SMW data
 * @obj: Data object
 *
 * Function calls the SMW API to delete data if data label
 * is supported.
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Bad arguments
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV libdev_delete_data(struct libobj_obj *obj);

/**
 * libdev_cancel_operation() - Cancel an on-going cryptographic multi-part operation.
 * @context - Double pointer to multi-part operation context.
 *
 * The multi-part operation context is released.
 *
 * Return:
 * CKR_DEVICE_ERROR                - Device failure
 * CKR_OK                          - Success
 */
CK_RV libdev_cancel_operation(void **context);

/**
 * libdev_copy_operation() - Copy an on-going cryptographic multi-part operation.
 * @src: The source operation context
 * @dst: The destination operation context
 *
 * Return:
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OBJECT_HANDLE_INVALID     - Object not found
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libdev_copy_operation(void *src, void **dst);

/**
 * libdev_add_opctx() - Add an active operation in device
 * @device: Reference to the library device
 * @op_flag: Operation flag
 * @mech: Mechanism definition
 * @ctx: Operation context
 * @cancel_operation: Pointer to cancel operation function
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_OPERATION_ACTIVE               - Operation is already initialized
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV libdev_add_opctx(struct libdevice *device, CK_FLAGS op_flag,
		       CK_MECHANISM_PTR mech, void *ctx,
		       CK_RV (*cancel_operation)(void *container,
						 struct libopctx *opctx));

/**
 * libdev_find_opctx() - Find an active device operation
 * @device: Reference to the library device
 * @op_flag: Operation flag
 * @mech: Mechanism definition
 * @ctx: Operation context
 *
 * If the operation mechanism @op_flag is present in the list,
 * returns the mechanism parameters in @mech and the operation
 * context in the @ctx.
 * Else return CKR_OPERATION_NOT_INITIALIZED error.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_OK                             - Success
 */
CK_RV libdev_find_opctx(struct libdevice *device, CK_FLAGS op_flag,
			CK_MECHANISM_PTR mech, void **ctx);

/**
 * libdev_remove_all_opctx() - Remove all active device operation
 * @device: Reference to the library device
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_OK                             - Success
 */
CK_RV libdev_remove_all_opctx(struct libdevice *device);

#endif /* __LIB_DEVICE_H__ */
