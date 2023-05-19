// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023 NXP
 */

#include "lib_cipher.h"

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_ENCRYPT);
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pData, ulDataLen, pEncryptedData,
				   pulEncryptedDataLen, CKF_ENCRYPT,
				   OP_ONE_SHOT);
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pPart, ulPartLen, pEncryptedPart,
				   pulEncryptedPartLen, CKF_ENCRYPT, OP_UPDATE);
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL, 0, pLastEncryptedPart,
				   pulLastEncryptedPartLen, CKF_ENCRYPT,
				   OP_FINAL);
}
