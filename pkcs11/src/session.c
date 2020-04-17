// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	(void)slotID;
	(void)flags;
	(void)pApplication;
	(void)Notify;
	(void)phSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	(void)slotID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	(void)hSession;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	(void)hSession;
	(void)flags;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	(void)hSession;
	(void)pOperationState;
	(void)pulOperationStateLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	(void)hSession;
	(void)pOperationState;
	(void)ulOperationStateLen;
	(void)hEncryptionKey;
	(void)hAuthenticationKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	(void)hSession;
	(void)userType;
	(void)pPin;
	(void)ulPinLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
		  CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	(void)hSession;
	(void)userType;
	(void)pPin;
	(void)ulPinLen;
	(void)pUsername;
	(void)ulUsernameLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
