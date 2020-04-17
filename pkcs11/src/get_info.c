// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <string.h>

#include "pkcs11smw.h"
#include "pkcs11smw_config.h"
#include "util.h"

#include "trace.h"

static struct CK_FUNCTION_LIST_3_0 pkcs11smw_v3_functions = {
	{ 3, 0 },
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent,
	&C_GetInterfaceList,
	&C_GetInterface,
	&C_LoginUser,
	&C_SessionCancel,
	&C_MessageEncryptInit,
	&C_EncryptMessage,
	&C_EncryptMessageBegin,
	&C_EncryptMessageNext,
	&C_MessageEncryptFinal,
	&C_MessageDecryptInit,
	&C_DecryptMessage,
	&C_DecryptMessageBegin,
	&C_DecryptMessageNext,
	&C_MessageDecryptFinal,
	&C_MessageSignInit,
	&C_SignMessage,
	&C_SignMessageBegin,
	&C_SignMessageNext,
	&C_MessageSignFinal,
	&C_MessageVerifyInit,
	&C_VerifyMessage,
	&C_VerifyMessageBegin,
	&C_VerifyMessageNext,
	&C_MessageVerifyFinal,
};

static struct CK_FUNCTION_LIST pkcs11smw_v2_functions = {
	{ 2, 40 },
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent,
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

static struct CK_INTERFACE pkcs11smw_interfaces[] = {
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
	{ 0 },
};

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	size_t len;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	DBG_TRACE("Copy %p to %p (%zu bytes)", pInfo, &pkcs11smw_info,
		  sizeof(pkcs11smw_info));
	memcpy(pInfo, &pkcs11smw_info, sizeof(pkcs11smw_info));

	/* Pad manufacturerID and LibraryDescription with blank */
	len = strlen((const char *)pkcs11smw_info.manufacturerID);
	DBG_TRACE("Manufacturer (%zu) bytes: %s", len, pInfo->manufacturerID);
	memset(pInfo->manufacturerID + len, ' ',
	       sizeof(pInfo->manufacturerID) - len);

	len = strlen((const char *)pkcs11smw_info.libraryDescription);
	DBG_TRACE("Lib Description (%zu) bytes: %s", len,
		  pInfo->libraryDescription);
	memset(pInfo->libraryDescription + len, ' ',
	       sizeof(pInfo->libraryDescription) - len);

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
	CK_ULONG nb_entries;

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
	CK_INTERFACE_PTR entry = pkcs11smw_interfaces;
	CK_FUNCTION_LIST_PTR func_list;

	if (!ppInterface)
		goto end;

	*ppInterface = NULL;

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
		*ppInterface = entry;
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
