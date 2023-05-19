// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023 NXP
 */

#include "lib_cipher.h"

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_DECRYPT);
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pEncryptedData, ulEncryptedDataLen,
				   pData, pulDataLen, CKF_DECRYPT, OP_ONE_SHOT);
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pEncryptedPart, ulEncryptedPartLen,
				   pPart, pulPartLen, CKF_DECRYPT, OP_UPDATE);
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL, 0, pLastPart, pulLastPartLen,
				   CKF_DECRYPT, OP_FINAL);
}
