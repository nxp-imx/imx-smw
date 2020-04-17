// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG_PTR pulPlaintextLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pAssociatedData;
	(void)ulAssociatedDataLen;
	(void)pCiphertext;
	(void)ulCiphertextLen;
	(void)pPlaintext;
	(void)pulPlaintextLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
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

CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertext,
			   CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
			   CK_ULONG_PTR pulPlaintextLen, CK_FLAGS flags)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pCiphertext;
	(void)ulCiphertextLen;
	(void)pPlaintext;
	(void)pulPlaintextLen;
	(void)flags;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
