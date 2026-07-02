// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020; 2026 NXP
 */

#include "pkcs11smw.h"

/**
 * C_DigestEncryptUpdate() - Continue multi-part digest and encryption.
 * @hSession: [in] Session's handle.
 * @pPart: [in] Data part to digest and encrypt.
 * @ulPartLen: [in] Length of data part in bytes.
 * @pEncryptedPart: [out] Encrypted data part.
 * @pulEncryptedPartLen: [in/out] Length of encrypted data part in bytes.
 *
 * This function continues a multi-part dual operation, processing another
 * data part for both digesting and encryption operations.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
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

/**
 * C_DecryptDigestUpdate() - Continue multi-part decryption and digest.
 * @hSession: [in] Session's handle.
 * @pEncryptedPart: [in] Encrypted data part to decrypt and digest.
 * @ulEncryptedPartLen: [in] Length of encrypted data part in bytes.
 * @pPart: [out] Decrypted data part.
 * @pulPartLen: [in/out] Length of decrypted data part in bytes.
 *
 * This function continues a multi-part dual operation, processing another
 * encrypted data part for both decryption and digesting operations.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
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

/**
 * C_SignEncryptUpdate() - Continue multi-part signing and encryption.
 * @hSession: [in] Session's handle.
 * @pPart: [in] Data part to sign and encrypt.
 * @ulPartLen: [in] Length of data part in bytes.
 * @pEncryptedPart: [out] Encrypted data part.
 * @pulEncryptedPartLen: [in/out] Length of encrypted data part in bytes.
 *
 * This function continues a multi-part dual operation, processing another
 * data part for both signing and encryption operations.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
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

/**
 * C_DecryptVerifyUpdate() - Continue multi-part decryption and verification.
 * @hSession: [in] Session's handle.
 * @pEncryptedPart: [in] Encrypted data part to decrypt and verify.
 * @ulEncryptedPartLen: [in] Length of encrypted data part in bytes.
 * @pPart: [out] Decrypted data part.
 * @pulPartLen: [in/out] Length of decrypted data part in bytes.
 *
 * This function continues a multi-part dual operation, processing another
 * encrypted data part for both decryption and signature verification operations.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
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
