// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023 NXP
 */

#include "lib_context.h"
#include "lib_device.h"

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
	if (tokenPresent)
		ret = libdev_get_slots_present(&nb_slots, pSlotList);
	else
		ret = libdev_get_slots(&nb_slots, pSlotList);

	if (!pSlotList && ret == CKR_OK)
		*pulCount = nb_slots;

	return ret;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libdev_get_slotinfo(slotID, pInfo);
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libdev_get_tokeninfo(slotID, pInfo);
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
			 CK_VOID_PTR pRserved)
{
	(void)flags;
	(void)pSlot;
	(void)pRserved;

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

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libdev_get_mechanism_info(slotID, type, pInfo);
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	(void)pPin;
	(void)ulPinLen;

	if (!pLabel)
		return CKR_ARGUMENTS_BAD;

	return libdev_init_token(slotID, pLabel);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	(void)hSession;
	(void)pPin;
	(void)ulPinLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

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
