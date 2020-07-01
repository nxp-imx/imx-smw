// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	(void)hSession;
	(void)pTemplate;
	(void)ulCount;
	(void)phObject;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		   CK_OBJECT_HANDLE_PTR phNewObject)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;
	(void)phNewObject;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	(void)hSession;
	(void)hObject;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		      CK_ULONG_PTR pulSize)
{
	(void)hSession;
	(void)hObject;
	(void)pulSize;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	(void)hSession;
	(void)pTemplate;
	(void)ulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	(void)hSession;
	(void)phObject;
	(void)ulMaxObjectCount;
	(void)pulObjectCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}