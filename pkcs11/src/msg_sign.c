// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024-2025 NXP
 */

#include "lib_sign_verify.h"
#include "lib_session.h"

CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_sign_verify_init(hSession, pMechanism, hKey,
				    CKF_MESSAGE_SIGN);
}

CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		    CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign(hSession, pParameter, ulParameterLen, pData, ulDataLen,
			pSignature, pulSignatureLen, CKF_MESSAGE_SIGN,
			OP_ONE_SHOT);
}

CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			 CK_ULONG ulParameterLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign_verify_reset(hSession, pParameter, ulParameterLen,
				     CKF_MESSAGE_SIGN);
}

CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulSignatureLen)
{
	enum op_state state = NOT_INIT;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (pulSignatureLen)
		state = OP_END;
	else
		state = OP_NEXT;

	return lib_sign(hSession, pParameter, ulParameterLen, pData, ulDataLen,
			pSignature, pulSignatureLen, CKF_MESSAGE_SIGN, state);
}

CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	return libsess_cancel_opctx(hSession, CKF_MESSAGE_SIGN);
}
