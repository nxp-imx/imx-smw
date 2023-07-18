// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include "pkcs11smw.h"

#include "lib_session.h"
#include "lib_device.h"
#include "lib_digest.h"

static CK_RV digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	CK_MECHANISM mechanism = { 0 };
	struct libdig_params params = { 0 };

	if (!hSession)
		return ret;

	if ((pDigest && (!pData != !ulDataLen)) || !pulDigestLen) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	ret = libsess_find_opctx(hSession, CKF_DIGEST, &mechanism, NULL);
	if (ret != CKR_OK)
		goto end;

	params.pData = pData;
	params.ulDataLen = ulDataLen;
	params.pDigest = pDigest;
	params.pulDigestLen = pulDigestLen;

	ret = libdev_operate_mechanism(hSession, &mechanism, &params);

end:
	if (ret == CKR_OK && pDigest)
		ret = libsess_remove_opctx(hSession, CKF_DIGEST);
	else if (ret != CKR_OK && ret != CKR_BUFFER_TOO_SMALL)
		(void)libsess_remove_opctx(hSession, CKF_DIGEST);

	return ret;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;

	if (!hSession)
		return ret;

	if (pMechanism) {
		ret = libsess_validate_mechanism(hSession, pMechanism,
						 CKF_DIGEST);
		if (ret != CKR_OK)
			return ret;

		ret = libsess_add_opctx(hSession, CKF_DIGEST, pMechanism, NULL);
	} else {
		ret = libsess_remove_opctx(hSession, CKF_DIGEST);
	}

	return ret;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	return digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	return digest(hSession, NULL_PTR, 0, pDigest, pulDigestLen);
}
