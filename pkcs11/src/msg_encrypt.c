// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG_PTR pulCiphertextLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pAssociatedData;
	(void)ulAssociatedDataLen;
	(void)pPlaintext;
	(void)ulPlaintextLen;
	(void)pCiphertext;
	(void)pulCiphertextLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen,
			    CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pAssociatedData;
	(void)ulAssociatedDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart,
			   CK_ULONG ulPlaintextPartLen,
			   CK_BYTE_PTR pCiphertextPart,
			   CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pPlaintextPart;
	(void)ulPlaintextPartLen;
	(void)pCiphertextPart;
	(void)pulCiphertextPartLen;
	(void)flags;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
