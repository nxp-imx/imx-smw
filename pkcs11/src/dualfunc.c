// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
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

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
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

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
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

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
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
