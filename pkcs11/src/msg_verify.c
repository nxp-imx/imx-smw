// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024 NXP
 */

#include "lib_sign_verify.h"

CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_sign_verify_init(hSession, pMechanism, hKey, CKF_VERIFY);
}

CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		      CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		      CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_verify(hSession, pParameter, ulParameterLen, pData,
			  ulDataLen, pSignature, ulSignatureLen);
}

CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			  CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			  CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)ulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
