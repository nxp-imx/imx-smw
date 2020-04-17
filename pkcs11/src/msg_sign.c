// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		    CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			 CK_ULONG ulParameterLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
