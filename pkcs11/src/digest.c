// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2025 NXP
 */

#include "pkcs11smw.h"

#include "lib_session.h"
#include "lib_device.h"
#include "lib_digest.h"

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest_init(hSession, pMechanism);
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest(hSession, pData, ulDataLen, pDigest, pulDigestLen,
			  OP_ONE_SHOT);
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest(hSession, pPart, ulPartLen, NULL_PTR, NULL_PTR,
			  OP_UPDATE);
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_digest_key(hSession, hKey);
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest(hSession, NULL_PTR, 0, pDigest, pulDigestLen,
			  OP_FINAL);
}
