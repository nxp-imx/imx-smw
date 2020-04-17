// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pEncryptedData;
	(void)ulEncryptedDataLen;
	(void)pData;
	(void)pulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	(void)hSession;
	(void)pLastPart;
	(void)pulLastPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
