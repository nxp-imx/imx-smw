/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
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
 * @nb_slots: Number of slots
 * @slotlist: List of slots
 *
 * Return the number of slots in @nb_slots and if @slotlist not
 * NULL, fill the list of slots.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_BUFFER_TOO_SMALL          - Pointer to the list buffer too small
 * CKR_OK                        - Success
 *
 */
CK_RV libdev_get_slots(CK_ULONG_PTR nb_slots, CK_SLOT_ID_PTR slotlist);

/**
 * libdev_get_slots_present() - Return the slots present
 * @nb_slots: Number of slots present
 * @slotlist: List of slots present
 *
 * Return the number of slots present in @nb_slots and if @slotlist not
 * NULL, fill the list of slot present.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_BUFFER_TOO_SMALL          - Pointer to the list buffer too small
 * CKR_OK                        - Success
 */
CK_RV libdev_get_slots_present(CK_ULONG_PTR nb_slots, CK_SLOT_ID_PTR slotlist);

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
				CK_MECHANISM_INFO_PTR info);

/**
 * libdev_validate_mechanism() - Validate mechanism
 * @slotid: Slot ID
 * @mech: Mechanism definition
 *
 * Checks if a slot ID is supporting given mechanism
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT         - Token is not present
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_OK                        - Success
 */
CK_RV libdev_validate_mechanism(CK_SLOT_ID slotid, CK_MECHANISM_PTR mech);

/**
 * libdev_operate_mechanism() - Operate the mechanism calling SMW APIs
 * @hsession: Session handle
 * @mech: Mechanism definition
 * @args: SMW API arguments
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
 * CKR_OK                        - Success
 */
CK_RV libdev_operate_mechanism(CK_SESSION_HANDLE hsession,
			       CK_MECHANISM_PTR mech, void *args);

/**
 * libdev_delete_key() - Call SMW delete key API
 * @key_id: Key id to deleete
 *
 * Function build the SMW API argument to delete a key in the session's
 * subsystem.
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Key id is 0
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV libdev_delete_key(unsigned long long key_id);

/**
 * libdev_mechanisms_init() - Initialize the device mechanism information
 * @slotid: Slot ID
 *
 * Return:
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_OK                        - Success
 */
CK_RV libdev_mechanisms_init(CK_SLOT_ID slotid);

#endif /* __LIB_DEVICE_H__ */
