// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023-2026 NXP
 */

#include "lib_context.h"
#include "lib_device.h"

/**
 * C_GetSlotList() - Obtains a list of slots in the system.
 * @tokenPresent: [in] Indicates whether the list returned includes only those
 *                     slots with a token present (CK_TRUE), or all slots
 *                     (CK_FALSE).
 * @pSlotList: [out] Pointer to the location that receives the array of slot
 *                   IDs, or :c:macro:`NULL_PTR` to query the number of slots.
 * @pulCount: [in/out] Pointer to a location that gives the number elements in
 *                     @pSlotList, or receives the number of slots.
 *
 * This function is used to obtain a list of slots in the system.
 * A slot is a logical reader that potentially contains a token.
 *
 * If @pSlotList is :c:macro:`NULL_PTR`, the function returns the total
 * number of supported slots in @pulCount.
 *
 * If the @pSlotList is not :c:macro:`NULL_PTR`, the @pulCount contains
 * the number of elements in @pSlotList on input, and receives the number
 * of slots actually copied on output. If the buffer is too small to hold
 * all slot identifiers, the function returns CKR_BUFFER_TOO_SMALL, otherwise
 * the function copies all slot identifiers into the @pSlotList.
 *
 * Return:
 *  - CKR_OK
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pulCount is NULL.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The buffer provided is too small.
 *  - CKR_ERROR_GENERAL:
 *      No slot available.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
		    CK_ULONG_PTR pulCount)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	CK_ULONG nb_slots = 0;

	if (!pulCount)
		return ret;

	if (pSlotList)
		nb_slots = *pulCount;

	/*
	 * Caller ask only the list of the Slot present
	 * if @tokenPresent is true
	 */
	ret = libdev_get_slots(&nb_slots, pSlotList, tokenPresent);

	if (!pSlotList && ret == CKR_OK)
		*pulCount = nb_slots;

	return ret;
}

/**
 * C_GetSlotInfo() - Obtains information about a particular slot in the system.
 * @slotID: [in] The ID of the slot.
 * @pInfo:  [out] Pointer to the location that receives the slot information.
 *
 * This function obtains information about a particular slot in the system.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pInfo is NULL.
 *  - CKR_SLOT_ID_INVALID:
 *      The slot ID is not valid.
 *  - CKR_ERROR_GENERAL:
 *      No slot available.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libdev_get_slotinfo(slotID, pInfo);
}

/**
 * C_GetTokenInfo() - Obtains information about a particular token in the system.
 * @slotID: [in] The ID of the token's slot.
 * @pInfo: [out] Pointer to the location that receives the token information.
 *
 * This function obtains information about a particular token in the system.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pInfo is NULL.
 *  - CKR_SLOT_ID_INVALID:
 *      The slot ID is not valid.
 *  - CKR_ERROR_GENERAL:
 *      General error.
 *  - CKR_FUNCTION_FAILED:
 *      Failure in the function.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libdev_get_tokeninfo(slotID, pInfo);
}

/**
 * C_WaitForSlotEvent() - Waits for a slot event.
 * @flags: [in] Determines whether or not the function blocks.
 * @pSlot: [in] Pointer to the location that receives the slot ID.
 * @pReserved: Reserved for future use, should be :c:macro:`NULL_PTR`.
 *
 * This function waits for a slot event, such as token insertion or removal,
 * to occur.
 *
 * Only one flag is supported: :c:macro:`CKF_DONT_BLOCK`. If this flag is set\:
 *
 *   - If some slot's event is pending, the event is cleared and the function
 *     returns with the ID of the slot in @pSlot.
 *   - If no slot's event is pending, the function returns with the value
 *     CKR_NO_EVENT. The content of the @pSlot is no signicant.
 *
 * .. note::
 *    As the device supported is not a removal device, this functionality
 *    is not supported.
 *
 * Return:
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *     Function is not supported.
 */
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
			 CK_VOID_PTR pReserved)
{
	(void)flags;
	(void)pSlot;
	(void)pReserved;

	CK_RV ret = CKR_OK;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	/*
	 * Devices are not removable, hence function is not
	 * supported.
	 */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_GetMechanismList() - Obtains a list of mechanism types supported by a token.
 * @slotID: [in] The ID of the token's slot.
 * @pMechanismList: [out] Pointer to the location that receives the array of
 *                        mechanism types, or :c:macro:`NULL_PTR` to query the
 *                        number of mechanisms.
 * @pulCount: [in/out] Pointer to the location that gives the number of elements
 *                     in @pMechanismList, or receives the number of mechanisms
 *
 * This function is used to obtain a list of mechanism types supported by a
 * token.
 *
 * If @pMechanismList is :c:macro:`NULL_PTR`, the function returns the total
 * number of supported mechanisms in @pulCount.
 *
 * If the @pMechanismList is not :c:macro:`NULL_PTR`, the @pulCount contains
 * the number of elements in @pMechanismList on input, and receives the number
 * of mechanisms actually copied on output. If the buffer is too small to hold
 * all mechanisms, the function returns CKR_BUFFER_TOO_SMALL, otherwise
 * the function copies all mechanisms into the @pMechanismList.
 *
 * Return:
 *  - CKR_OK
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pulCount is NULL.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The buffer provided is too small.
 *  - CKR_HOST_MEMORY:
 *      Memory allocation failed.
 *  - CKR_TOKEN_NOT_PRESENT:
 *      The token is not present.
 *  - CKR_SLOT_ID_INVALID:
 *      The slot ID is not valid.
 *  - CKR_ERROR_GENERAL:
 *      No slot available.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	CK_ULONG nb_mechanisms = 0;

	if (!pulCount)
		return ret;

	if (pMechanismList)
		nb_mechanisms = *pulCount;

	ret = libdev_get_mechanisms(slotID, pMechanismList, &nb_mechanisms);

	if (!pMechanismList && ret == CKR_OK)
		*pulCount = nb_mechanisms;

	return ret;
}

/**
 * C_GetMechanismInfo() - Obtains information about a particular mechanism.
 * @slotID: [in] The ID of the token's slot.
 * @type: [in] The type of mechanism.
 * @pInfo: [out] Pointer to the location that receives the mechanism information.
 *
 * This function obtains information about a particular mechanism possibly
 * supported by a token.
 *
 * Return:
 *  - CKR_OK
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pInfo is NULL.
 *  - CKR_MECHANISM_INVALID:
 *      The mechanism @type is not valid.
 *  - CKR_TOKEN_NOT_PRESENT:
 *      The token is not present.
 *  - CKR_SLOT_ID_INVALID:
 *      The slot ID is not valid.
 *  - CKR_ERROR_GENERAL:
 *      No slot available.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libdev_get_mechanism_info(slotID, type, pInfo, 0);
}

/**
 * C_InitToken() - Initializes a token.
 * @slotID: [in] The ID of the token's slot.
 * @pPin: [in] The SO's initial PIN (not used in this implementation).
 * @ulPinLen: [in] The length in bytes of the PIN (not used in this
 *                 implementation).
 * @pLabel: [out] Pointer to the 32-byte token label (blank padded).
 *
 * This function initializes a token. The token label is set and the token
 * is prepared for use.
 *
 * .. note::
 *    This implementation does not support PIN management.
 *
 * Return:
 *  - CKR_OK
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pLabel is NULL.
 *  - CKR_TOKEN_NOT_PRESENT:
 *      The token is not present.
 *  - CKR_SESSION_EXISTS:
 *      A session is already open with the token.
 *  - CKR_SLOT_ID_INVALID:
 *      The slot ID is not valid.
 *  - CKR_ERROR_GENERAL:
 *      No slot available.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	(void)pPin;
	(void)ulPinLen;

	if (!pLabel)
		return CKR_ARGUMENTS_BAD;

	return libdev_init_token(slotID, pLabel);
}

/**
 * C_InitPIN() - Initializes the normal user's PIN.
 * @hSession: [in] The session's handle.
 * @pPin: [in] The normal user's PIN.
 * @ulPinLen: [in] The length in bytes of the PIN.
 *
 * This function initializes the normal user's PIN.
 *
 * .. note::
 *    This implementation does not support PIN management.
 *
 * Return:
 *   - CKR_FUNCTION_NOT_SUPPORTED:
 *       Function is not supported.
 */
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	(void)hSession;
	(void)pPin;
	(void)ulPinLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_SetPIN() - Modifies the PIN of the user that is currently logged in.
 * @hSession: [in] The session's handle
 * @pOldPin: [in] The old PIN
 * @ulOldLen: [in] The length in bytes of the old PIN
 * @pNewPin: [in] The new PIN
 * @ulNewLen: [in] The length in bytes of the new PIN
 *
 * This function modifies the PIN of the user who is currently logged in,
 * or the CKU_USER PIN if the session is not logged in.
 *
 * .. note::
 *    This implementation does not support PIN management.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function is not supported.
 */
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	(void)hSession;
	(void)pOldPin;
	(void)ulOldLen;
	(void)pNewPin;
	(void)ulNewLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
