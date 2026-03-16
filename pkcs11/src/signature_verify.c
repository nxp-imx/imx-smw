// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "lib_session.h"

CK_RV C_VerifySignatureInit(CK_SESSION_HANDLE hSession,
			    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey,
			    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;
	(void)pSignature;
	(void)ulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			      CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
