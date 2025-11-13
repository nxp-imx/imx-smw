// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024-2025 NXP
 */

#include "lib_cipher.h"
#include "lib_session.h"

CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_MESSAGE_DECRYPT);
}

CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG_PTR pulPlaintextLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   pAssociatedData, ulAssociatedDataLen,
				   pCiphertext, ulCiphertextLen, pPlaintext,
				   pulPlaintextLen, CKF_MESSAGE_DECRYPT,
				   OP_ONE_SHOT);
}

CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen,
			    CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt_reset(hSession, pParameter, ulParameterLen,
					 pAssociatedData, ulAssociatedDataLen,
					 CKF_MESSAGE_DECRYPT);
}

CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertext,
			   CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
			   CK_ULONG_PTR pulPlaintextLen, CK_FLAGS flags)
{
	enum op_state state = NOT_INIT;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (flags & CKF_END_OF_MESSAGE)
		state = OP_END;
	else
		state = OP_NEXT;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   NULL_PTR, 0, pCiphertext, ulCiphertextLen,
				   pPlaintext, pulPlaintextLen,
				   CKF_MESSAGE_DECRYPT, state);
}

CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
	return libsess_cancel_opctx(hSession, CKF_MESSAGE_DECRYPT);
}
