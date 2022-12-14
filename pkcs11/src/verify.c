// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "lib_sign_verify.h"

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_sign_verify_init(hSession, pMechanism, hKey, CKF_VERIFY);
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_verify(hSession, pData, ulDataLen, pSignature,
			  ulSignatureLen);
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;
	(void)pData;
	(void)pulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
