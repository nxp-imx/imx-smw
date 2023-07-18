// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include "lib_object.h"

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pTemplate || !ulCount)
		return CKR_TEMPLATE_INCOMPLETE;

	if (!phObject)
		return CKR_ARGUMENTS_BAD;

	return libobj_create(hSession, pTemplate, ulCount, phObject);
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
	return libobj_destroy(hSession, hObject);
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
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pTemplate || !ulCount)
		return CKR_TEMPLATE_INCOMPLETE;

	if (!hObject)
		return CKR_ARGUMENTS_BAD;

	return libobj_get_attribute(hSession, hObject, pTemplate, ulCount);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pTemplate || !ulCount)
		return CKR_TEMPLATE_INCOMPLETE;

	if (!hObject)
		return CKR_ARGUMENTS_BAD;

	return libobj_modify_attribute(hSession, hObject, pTemplate, ulCount);
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	/* ulCount=0 is valid and will find all objects */
	if ((pTemplate && !ulCount) || (!pTemplate && ulCount))
		return CKR_ARGUMENTS_BAD;

	return libobj_find_init(hSession, pTemplate, ulCount);
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!phObject || !pulObjectCount)
		return CKR_ARGUMENTS_BAD;

	if (!ulMaxObjectCount) {
		/*
		 * If size of object handles is 0, assume it's valid
		 * but return 0 object found.
		 */
		*pulObjectCount = 0;
		return CKR_OK;
	}

	return libobj_find(hSession, phObject, ulMaxObjectCount,
			   pulObjectCount);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return libobj_find_final(hSession);
}
