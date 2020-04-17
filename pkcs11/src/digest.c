// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	(void)hSession;
	(void)pMechanism;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pDigest;
	(void)pulDigestLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pDigest;
	(void)pulDigestLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
