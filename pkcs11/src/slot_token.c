// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
		    CK_ULONG_PTR pulCount)
{
	(void)tokenPresent;
	(void)pSlotList;
	(void)pulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	(void)slotID;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	(void)slotID;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
			 CK_VOID_PTR pRserved)
{
	(void)flags;
	(void)pSlot;
	(void)pRserved;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	(void)slotID;
	(void)pMechanismList;
	(void)pulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	(void)slotID;
	(void)type;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	(void)slotID;
	(void)pPin;
	(void)ulPinLen;
	(void)pLabel;

	return CKR_FUNCTION_NOT_SUPPORTED;
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
