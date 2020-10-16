// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "lib_object.h"

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pMechanism)
		return CKR_MECHANISM_PARAM_INVALID;

	/*
	 * Key template attributes may not be necessary
	 */
	if ((!pTemplate && ulCount) || (pTemplate && !ulCount))
		return CKR_TEMPLATE_INCOMPLETE;

	if (!phKey)
		return CKR_ARGUMENTS_BAD;

	return libobj_generate_key(hSession, pMechanism, pTemplate, ulCount,
				   phKey);
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pMechanism)
		return CKR_MECHANISM_PARAM_INVALID;

	if (!pPublicKeyTemplate || !ulPublicKeyAttributeCount)
		return CKR_TEMPLATE_INCOMPLETE;

	/*
	 * Private key template attributes may not be necessary
	 */
	if ((!pPrivateKeyTemplate && ulPrivateKeyAttributeCount) ||
	    (pPrivateKeyTemplate && !ulPrivateKeyAttributeCount))
		return CKR_TEMPLATE_INCOMPLETE;

	if (!phPublicKey || !phPrivateKey)
		return CKR_ARGUMENTS_BAD;

	return libobj_generate_keypair(hSession, pMechanism, pPublicKeyTemplate,
				       ulPublicKeyAttributeCount,
				       pPrivateKeyTemplate,
				       ulPrivateKeyAttributeCount, phPublicKey,
				       phPrivateKey);
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	(void)hSession;
	(void)pMechanism;
	(void)hWrappingKey;
	(void)hKey;
	(void)pWrappedKey;
	(void)pulWrappedKeyLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hUnwrappingKey;
	(void)pWrappedKey;
	(void)ulWrappedKeyLen;
	(void)pTemplate;
	(void)ulAttributeCount;
	(void)phKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hBaseKey;
	(void)pTemplate;
	(void)ulAttributeCount;
	(void)phKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
