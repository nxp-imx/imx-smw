// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023-2026 NXP
 */

#include <string.h>

#include "pkcs11smw.h"
#include "pkcs11smw_config.h"
#include "util.h"

#include "trace.h"

#define VERSION(_major, _minor) .version = { .major = _major, .minor = _minor }

#define FUNCTION(_field, _name) ._field = _name

static struct CK_FUNCTION_LIST_3_2 pkcs11smw_v3_functions = {
	VERSION(3, 2),
	FUNCTION(C_Initialize, C_Initialize),
	FUNCTION(C_Finalize, C_Finalize),
	FUNCTION(C_GetInfo, C_GetInfo),
	FUNCTION(C_GetFunctionList, C_GetFunctionList),
	FUNCTION(C_GetSlotList, C_GetSlotList),
	FUNCTION(C_GetSlotInfo, C_GetSlotInfo),
	FUNCTION(C_GetTokenInfo, C_GetTokenInfo),
	FUNCTION(C_GetMechanismList, C_GetMechanismList),
	FUNCTION(C_GetMechanismInfo, C_GetMechanismInfo),
	FUNCTION(C_InitToken, C_InitToken),
	FUNCTION(C_InitPIN, C_InitPIN),
	FUNCTION(C_SetPIN, C_SetPIN),
	FUNCTION(C_OpenSession, C_OpenSession),
	FUNCTION(C_CloseSession, C_CloseSession),
	FUNCTION(C_CloseAllSessions, C_CloseAllSessions),
	FUNCTION(C_GetSessionInfo, C_GetSessionInfo),
	FUNCTION(C_GetOperationState, C_GetOperationState),
	FUNCTION(C_SetOperationState, C_SetOperationState),
	FUNCTION(C_Login, C_Login),
	FUNCTION(C_Logout, C_Logout),
	FUNCTION(C_CreateObject, C_CreateObject),
	FUNCTION(C_CopyObject, C_CopyObject),
	FUNCTION(C_DestroyObject, C_DestroyObject),
	FUNCTION(C_GetObjectSize, C_GetObjectSize),
	FUNCTION(C_GetAttributeValue, C_GetAttributeValue),
	FUNCTION(C_SetAttributeValue, C_SetAttributeValue),
	FUNCTION(C_FindObjectsInit, C_FindObjectsInit),
	FUNCTION(C_FindObjects, C_FindObjects),
	FUNCTION(C_FindObjectsFinal, C_FindObjectsFinal),
	FUNCTION(C_EncryptInit, C_EncryptInit),
	FUNCTION(C_Encrypt, C_Encrypt),
	FUNCTION(C_EncryptUpdate, C_EncryptUpdate),
	FUNCTION(C_EncryptFinal, C_EncryptFinal),
	FUNCTION(C_DecryptInit, C_DecryptInit),
	FUNCTION(C_Decrypt, C_Decrypt),
	FUNCTION(C_DecryptUpdate, C_DecryptUpdate),
	FUNCTION(C_DecryptFinal, C_DecryptFinal),
	FUNCTION(C_DigestInit, C_DigestInit),
	FUNCTION(C_Digest, C_Digest),
	FUNCTION(C_DigestUpdate, C_DigestUpdate),
	FUNCTION(C_DigestKey, C_DigestKey),
	FUNCTION(C_DigestFinal, C_DigestFinal),
	FUNCTION(C_SignInit, C_SignInit),
	FUNCTION(C_Sign, C_Sign),
	FUNCTION(C_SignUpdate, C_SignUpdate),
	FUNCTION(C_SignFinal, C_SignFinal),
	FUNCTION(C_SignRecoverInit, C_SignRecoverInit),
	FUNCTION(C_SignRecover, C_SignRecover),
	FUNCTION(C_VerifyInit, C_VerifyInit),
	FUNCTION(C_Verify, C_Verify),
	FUNCTION(C_VerifyUpdate, C_VerifyUpdate),
	FUNCTION(C_VerifyFinal, C_VerifyFinal),
	FUNCTION(C_VerifyRecoverInit, C_VerifyRecoverInit),
	FUNCTION(C_VerifyRecover, C_VerifyRecover),
	FUNCTION(C_DigestEncryptUpdate, C_DigestEncryptUpdate),
	FUNCTION(C_DecryptDigestUpdate, C_DecryptDigestUpdate),
	FUNCTION(C_SignEncryptUpdate, C_SignEncryptUpdate),
	FUNCTION(C_DecryptVerifyUpdate, C_DecryptVerifyUpdate),
	FUNCTION(C_GenerateKey, C_GenerateKey),
	FUNCTION(C_GenerateKeyPair, C_GenerateKeyPair),
	FUNCTION(C_WrapKey, C_WrapKey),
	FUNCTION(C_UnwrapKey, C_UnwrapKey),
	FUNCTION(C_DeriveKey, C_DeriveKey),
	FUNCTION(C_SeedRandom, C_SeedRandom),
	FUNCTION(C_GenerateRandom, C_GenerateRandom),
	FUNCTION(C_GetFunctionStatus, C_GetFunctionStatus),
	FUNCTION(C_CancelFunction, C_CancelFunction),
	FUNCTION(C_WaitForSlotEvent, C_WaitForSlotEvent),
	FUNCTION(C_GetInterfaceList, C_GetInterfaceList),
	FUNCTION(C_GetInterface, C_GetInterface),
	FUNCTION(C_LoginUser, C_LoginUser),
	FUNCTION(C_SessionCancel, C_SessionCancel),
	FUNCTION(C_MessageEncryptInit, C_MessageEncryptInit),
	FUNCTION(C_EncryptMessage, C_EncryptMessage),
	FUNCTION(C_EncryptMessageBegin, C_EncryptMessageBegin),
	FUNCTION(C_EncryptMessageNext, C_EncryptMessageNext),
	FUNCTION(C_MessageEncryptFinal, C_MessageEncryptFinal),
	FUNCTION(C_MessageDecryptInit, C_MessageDecryptInit),
	FUNCTION(C_DecryptMessage, C_DecryptMessage),
	FUNCTION(C_DecryptMessageBegin, C_DecryptMessageBegin),
	FUNCTION(C_DecryptMessageNext, C_DecryptMessageNext),
	FUNCTION(C_MessageDecryptFinal, C_MessageDecryptFinal),
	FUNCTION(C_MessageSignInit, C_MessageSignInit),
	FUNCTION(C_SignMessage, C_SignMessage),
	FUNCTION(C_SignMessageBegin, C_SignMessageBegin),
	FUNCTION(C_SignMessageNext, C_SignMessageNext),
	FUNCTION(C_MessageSignFinal, C_MessageSignFinal),
	FUNCTION(C_MessageVerifyInit, C_MessageVerifyInit),
	FUNCTION(C_VerifyMessage, C_VerifyMessage),
	FUNCTION(C_VerifyMessageBegin, C_VerifyMessageBegin),
	FUNCTION(C_VerifyMessageNext, C_VerifyMessageNext),
	FUNCTION(C_MessageVerifyFinal, C_MessageVerifyFinal),
	FUNCTION(C_EncapsulateKey, C_EncapsulateKey),
	FUNCTION(C_DecapsulateKey, C_DecapsulateKey),
	FUNCTION(C_VerifySignatureInit, C_VerifySignatureInit),
	FUNCTION(C_VerifySignature, C_VerifySignature),
	FUNCTION(C_VerifySignatureUpdate, C_VerifySignatureUpdate),
	FUNCTION(C_VerifySignatureFinal, C_VerifySignatureFinal),
	FUNCTION(C_GetSessionValidationFlags, C_GetSessionValidationFlags),
	FUNCTION(C_AsyncComplete, C_AsyncComplete),
	FUNCTION(C_AsyncGetID, C_AsyncGetID),
	FUNCTION(C_AsyncJoin, C_AsyncJoin),
	FUNCTION(C_WrapKeyAuthenticated, C_WrapKeyAuthenticated),
	FUNCTION(C_UnwrapKeyAuthenticated, C_UnwrapKeyAuthenticated),
};

static struct CK_FUNCTION_LIST pkcs11smw_v2_functions = {
	VERSION(2, 40),
	FUNCTION(C_Initialize, C_Initialize),
	FUNCTION(C_Finalize, C_Finalize),
	FUNCTION(C_GetInfo, C_GetInfo),
	FUNCTION(C_GetFunctionList, C_GetFunctionList),
	FUNCTION(C_GetSlotList, C_GetSlotList),
	FUNCTION(C_GetSlotInfo, C_GetSlotInfo),
	FUNCTION(C_GetTokenInfo, C_GetTokenInfo),
	FUNCTION(C_GetMechanismList, C_GetMechanismList),
	FUNCTION(C_GetMechanismInfo, C_GetMechanismInfo),
	FUNCTION(C_InitToken, C_InitToken),
	FUNCTION(C_InitPIN, C_InitPIN),
	FUNCTION(C_SetPIN, C_SetPIN),
	FUNCTION(C_OpenSession, C_OpenSession),
	FUNCTION(C_CloseSession, C_CloseSession),
	FUNCTION(C_CloseAllSessions, C_CloseAllSessions),
	FUNCTION(C_GetSessionInfo, C_GetSessionInfo),
	FUNCTION(C_GetOperationState, C_GetOperationState),
	FUNCTION(C_SetOperationState, C_SetOperationState),
	FUNCTION(C_Login, C_Login),
	FUNCTION(C_Logout, C_Logout),
	FUNCTION(C_CreateObject, C_CreateObject),
	FUNCTION(C_CopyObject, C_CopyObject),
	FUNCTION(C_DestroyObject, C_DestroyObject),
	FUNCTION(C_GetObjectSize, C_GetObjectSize),
	FUNCTION(C_GetAttributeValue, C_GetAttributeValue),
	FUNCTION(C_SetAttributeValue, C_SetAttributeValue),
	FUNCTION(C_FindObjectsInit, C_FindObjectsInit),
	FUNCTION(C_FindObjects, C_FindObjects),
	FUNCTION(C_FindObjectsFinal, C_FindObjectsFinal),
	FUNCTION(C_EncryptInit, C_EncryptInit),
	FUNCTION(C_Encrypt, C_Encrypt),
	FUNCTION(C_EncryptUpdate, C_EncryptUpdate),
	FUNCTION(C_EncryptFinal, C_EncryptFinal),
	FUNCTION(C_DecryptInit, C_DecryptInit),
	FUNCTION(C_Decrypt, C_Decrypt),
	FUNCTION(C_DecryptUpdate, C_DecryptUpdate),
	FUNCTION(C_DecryptFinal, C_DecryptFinal),
	FUNCTION(C_DigestInit, C_DigestInit),
	FUNCTION(C_Digest, C_Digest),
	FUNCTION(C_DigestUpdate, C_DigestUpdate),
	FUNCTION(C_DigestKey, C_DigestKey),
	FUNCTION(C_DigestFinal, C_DigestFinal),
	FUNCTION(C_SignInit, C_SignInit),
	FUNCTION(C_Sign, C_Sign),
	FUNCTION(C_SignUpdate, C_SignUpdate),
	FUNCTION(C_SignFinal, C_SignFinal),
	FUNCTION(C_SignRecoverInit, C_SignRecoverInit),
	FUNCTION(C_SignRecover, C_SignRecover),
	FUNCTION(C_VerifyInit, C_VerifyInit),
	FUNCTION(C_Verify, C_Verify),
	FUNCTION(C_VerifyUpdate, C_VerifyUpdate),
	FUNCTION(C_VerifyFinal, C_VerifyFinal),
	FUNCTION(C_VerifyRecoverInit, C_VerifyRecoverInit),
	FUNCTION(C_VerifyRecover, C_VerifyRecover),
	FUNCTION(C_DigestEncryptUpdate, C_DigestEncryptUpdate),
	FUNCTION(C_DecryptDigestUpdate, C_DecryptDigestUpdate),
	FUNCTION(C_SignEncryptUpdate, C_SignEncryptUpdate),
	FUNCTION(C_DecryptVerifyUpdate, C_DecryptVerifyUpdate),
	FUNCTION(C_GenerateKey, C_GenerateKey),
	FUNCTION(C_GenerateKeyPair, C_GenerateKeyPair),
	FUNCTION(C_WrapKey, C_WrapKey),
	FUNCTION(C_UnwrapKey, C_UnwrapKey),
	FUNCTION(C_DeriveKey, C_DeriveKey),
	FUNCTION(C_SeedRandom, C_SeedRandom),
	FUNCTION(C_GenerateRandom, C_GenerateRandom),
	FUNCTION(C_GetFunctionStatus, C_GetFunctionStatus),
	FUNCTION(C_CancelFunction, C_CancelFunction),
	FUNCTION(C_WaitForSlotEvent, C_WaitForSlotEvent),
};

/*
 * Define the Library information
 */
static const CK_INFO pkcs11smw_info = {
	.cryptokiVersion = { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	.manufacturerID = MANUFACTURER_ID,
	.flags = 0,
	.libraryDescription = LIBRARY_DESCRIPTION,
	.libraryVersion = { LIB_VER_MAJOR, LIB_VER_MINOR },
};

/*
 * Define all library's interfaces supported
 */
static const CK_CHAR def_if_name[] = "PKCS 11";
#define DEFAULT_INTERFACE_ENTRY 0

static const struct CK_INTERFACE pkcs11smw_interfaces[] = {
	{
		.pInterfaceName = (CK_CHAR *)def_if_name,
		.pFunctionList = &pkcs11smw_v2_functions,
		.flags = 0,
	},
	{
		.pInterfaceName = (CK_CHAR *)def_if_name,
		.pFunctionList = &pkcs11smw_v3_functions,
		.flags = 0,
	},
	{ 0 }
};

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	size_t len = 0;
	size_t memset_len = 0;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	DBG_TRACE("Copy %p to %p (%zu bytes)", pInfo, &pkcs11smw_info,
		  sizeof(pkcs11smw_info));
	memcpy(pInfo, &pkcs11smw_info, sizeof(pkcs11smw_info));

	/* Pad manufacturerID and LibraryDescription with blank */
	len = strlen((const char *)pkcs11smw_info.manufacturerID);
	DBG_TRACE("Manufacturer (%zu) bytes: %s", len, pInfo->manufacturerID);

	if (!SUB_OVERFLOW(sizeof(pInfo->manufacturerID), len, &memset_len))
		memset(pInfo->manufacturerID + len, ' ', memset_len);

	len = strlen((const char *)pkcs11smw_info.libraryDescription);
	DBG_TRACE("Lib Description (%zu) bytes: %s", len,
		  pInfo->libraryDescription);

	if (!SUB_OVERFLOW(sizeof(pInfo->libraryDescription), len, &memset_len))
		memset(pInfo->libraryDescription + len, ' ', memset_len);

	return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11smw_v2_functions;

	return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList,
			 CK_ULONG_PTR pulCount)
{
	CK_ULONG nb_entries = 0;

	if (!pulCount)
		return CKR_ARGUMENTS_BAD;

	nb_entries = ARRAY_SIZE(pkcs11smw_interfaces) - 1;
	if (!pInterfacesList) {
		*pulCount = nb_entries;
		return CKR_OK;
	}

	if (*pulCount < nb_entries)
		return CKR_BUFFER_TOO_SMALL;

	memcpy(pInterfacesList, pkcs11smw_interfaces,
	       nb_entries * sizeof(CK_INTERFACE));

	return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
		     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	const struct CK_INTERFACE *entry = pkcs11smw_interfaces;
	CK_FUNCTION_LIST_PTR func_list = NULL_PTR;

	if (!ppInterface)
		goto end;

	*ppInterface = NULL_PTR;

	if (!pInterfaceName && !pVersion && !flags) {
		DBG_TRACE("No criteria, return default entry %d",
			  DEFAULT_INTERFACE_ENTRY);
		entry = &entry[DEFAULT_INTERFACE_ENTRY];
		ret = CKR_OK;
		goto end;
	}

	for (; entry->pInterfaceName; entry++) {
		if (pInterfaceName) {
			if (strcmp((const char *)pInterfaceName,
				   (const char *)entry->pInterfaceName))
				continue;
		}

		if (pVersion) {
			func_list = (CK_FUNCTION_LIST_PTR)entry->pFunctionList;
			if (pVersion->major != func_list->version.major ||
			    pVersion->minor != func_list->version.minor)
				continue;
		}

		if ((entry->flags & flags) == flags) {
			ret = CKR_OK;
			break;
		}
	}

end:
	if (ret == CKR_OK) {
		*ppInterface = (CK_INTERFACE_PTR)entry;
		func_list = (CK_FUNCTION_LIST_PTR)entry->pFunctionList;
		DBG_TRACE("Interface:");
		DBG_TRACE("    Name: %s", entry->pInterfaceName);
		DBG_TRACE("    Function ver: %01d.%01d",
			  func_list->version.major, func_list->version.minor);
		DBG_TRACE("    Flags: 0x%lX", entry->flags);
	}

	DBG_TRACE("return 0x%08lX", ret);
	return ret;
}
