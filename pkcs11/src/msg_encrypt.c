// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024 NXP
 */

#include "lib_cipher.h"
#include "pkcs11smw.h"

CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	if (!pMechanism)
		return lib_cipher_cancel_operation(hSession,
						   CKF_MESSAGE_ENCRYPT);

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_MESSAGE_ENCRYPT);
}

CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG_PTR pulCiphertextLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   pAssociatedData, ulAssociatedDataLen,
				   pPlaintext, ulPlaintextLen, pCiphertext,
				   pulCiphertextLen, CKF_MESSAGE_ENCRYPT,
				   OP_ONE_SHOT);
}

CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen,
			    CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt_reset(hSession, pParameter, ulParameterLen,
					 pAssociatedData, ulAssociatedDataLen,
					 CKF_MESSAGE_ENCRYPT);
}

CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart,
			   CK_ULONG ulPlaintextPartLen,
			   CK_BYTE_PTR pCiphertextPart,
			   CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	enum op_state state = NOT_INIT;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (flags & CKF_END_OF_MESSAGE)
		state = OP_END;
	else
		state = OP_NEXT;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   NULL_PTR, 0, pPlaintextPart,
				   ulPlaintextPartLen, pCiphertextPart,
				   pulCiphertextPartLen, CKF_MESSAGE_ENCRYPT,
				   state);
}

CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
	return lib_cipher_cancel_operation(hSession, CKF_MESSAGE_ENCRYPT);
}
