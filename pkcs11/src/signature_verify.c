// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "lib_session.h"

/**
 * C_VerifySignatureInit() - Initialize a signature verification operation.
 * @hSession: [in] Session's handle.
 * @pMechanism: [in] Verification mechanism.
 * @hKey: [in] Verification key handle.
 * @pSignature: [in] Signature to verify.
 * @ulSignatureLen: [in] Length of signature in bytes.
 *
 * This function initializes a signature verification operation where the
 * signature is provided at initialization time rather than at finalization.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
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

/**
 * C_VerifySignature() - Verify a signature in a single-part operation.
 * @hSession: [in] Session's handle.
 * @pData: [in] Data to verify.
 * @ulDataLen: [in] Length of data in bytes.
 *
 * This function verifies a signature on data in a single operation.
 * The signature must have been provided during initialization with
 * C_VerifySignatureInit().
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_VerifySignatureUpdate() - Continue a multi-part signature verification.
 * @hSession: [in] Session's handle.
 * @pPart: [in] Data part to verify.
 * @ulPartLen: [in] Length of data part in bytes.
 *
 * This function continues a multi-part signature verification operation,
 * processing another data part. The signature must have been provided
 * during initialization with C_VerifySignatureInit().
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED
 *      Function not supported.
 */
CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			      CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_VerifySignatureFinal() - Finish a multi-part signature verification.
 * @hSession: [in] Session's handle.
 *
 * This function finishes a multi-part signature verification operation.
 * The signature must have been provided during initialization with
 * C_VerifySignatureInit().
 *
 * .. note::
 *    This function is not supported.
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED
 *      Function not supported.
 */
CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
