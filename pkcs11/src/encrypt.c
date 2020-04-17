// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pEncryptedData;
	(void)pulEncryptedDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	(void)hSession;
	(void)pLastEncryptedPart;
	(void)pulLastEncryptedPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
