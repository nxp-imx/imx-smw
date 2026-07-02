// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2026 NXP
 */

#include "lib_object.h"

/**
 * C_CreateObject() - Create a new object.
 * @hSession: [in] Session handle.
 * @pTemplate: [in] Pointer to the object's attribute template.
 * @ulCount: [in] Number of attributes in the template.
 * @phObject: [out] Pointer to location that receives the handle of the new
 *                  object.
 *
 * The function creates a new object from a template and returns the new
 * object's handle.
 *
 * If the attribute 'CKA_TOKEN' is set to 'CK_TRUE', the object is a token
 * object and will be stored in the token. Otherwise, it is a session object.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @phObject is NULL.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is not valid.
 *  - CKR_TEMPLATE_INCOMPLETE:
 *      The @pTemplate and @ulCount is incomplete or inconsistent.
 *  - CKR_TEMPLATE_INCONSISTENT:
 *      One of the template's attribute type must not be defined.
 *  - CKR_ATTRIBUTE_READ_ONLY:
 *      One attribute is read only
 *  - CKR_ATTRIBUTE_VALUE_INVALID:
 *      One of the template's attribute value is not valid.
 *  - CKR_HOST_MEMORY:
 *      Allocation error.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
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

/**
 * C_CopyObject() - Copy an object.
 * @hSession: [in] Session handle.
 * @hObject: [in] Handle of the object to be copied.
 * @pTemplate: [in] Pointer to attribute template for the new object.
 * @ulCount: [in] Number of attributes in the template.
 * @phNewObject: [out] Pointer to location that receives the handle of the copy.
 *
 * The function copies an object @hObject, creating a new object for the copy.
 *
 * .. note::
 *    This implementation does not support object copying.
 *
 * Return:
 *   - CKR_FUNCTION_NOT_SUPPORTED:
 *       Function is not supported.
 */
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

/**
 * C_DestroyObject() - Destroy an object.
 * @hSession: [in] Session handle.
 * @hObject: [in] Handle of the object to be destroyed.
 *
 * The function destroys a token or session object.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is not valid.
 *  - CKR_OBJECT_HANDLE_INVALID:
 *      The @hObject handle is not valid.
 *  - CKR_ACTION_PROHIBITED:
 *      - The object cannot be destroyed due to CKA_DESTROYABLE attribute.
 *      - The session is read-only.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hObject)
		return CKR_OBJECT_HANDLE_INVALID;

	return libobj_destroy(hSession, hObject);
}

/**
 * C_GetObjectSize() - Get the size of an object.
 * @hSession: [in] Session handle.
 * @hObject: [in] Handle of the object.
 * @pulSize: [out] Pointer to location that receives the size in bytes.
 *
 * The function returns the size in bytes of an object in bytes:
 *
 *   - For a key object: the size of the private or secret key.
 *   - For a certificate object: the size of the certificate data.
 *   - For a data object: the size of the data.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      - The @hObject is NULL.
 *      - The @pulSize is NULL.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is not valid.
 *  - CKR_OBJECT_HANDLE_INVALID:
 *      The @hObject handle is not valid.
 *  - CKR_ACTION_PROHIBITED:
 *      - The object cannot be destroyed due to CKA_DESTROYABLE attribute.
 *      - The session is read-only.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		      CK_ULONG_PTR pulSize)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hObject || !pulSize)
		return CKR_ARGUMENTS_BAD;

	return libobj_get_size(hSession, hObject, pulSize);
}

/**
 * C_GetAttributeValue() - Get the value of one or more attributes of an object.
 * @hSession: [in] Session handle.
 * @hObject: [in] Handle of the object.
 * @pTemplate: [in/out] Pointer to template that specifies which attributes to
 *                      get.
 * @ulCount: [in] Number of attributes in the template.
 *
 * The function obtains the value of one or more attributes of an object.
 * The function is parsing the template to get the requested attributes, while
 * there is no fatal failure (error other than CKR_ATTRIBUTE_TYPE_INVALID,
 * CKR_BUFFER_TOO_SMALL, CKR_ATTRIBUTE_SENSITIVE), function continues to
 * parse the template. At the end, the first error encountered is returned.
 *
 * Setting the 'pValue' of the template to NULL will return the size of the
 * attribute value in the 'ulValueLen' field without returning error.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @hObject is NULL.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is not valid.
 *  - CKR_TEMPLATE_INCOMPLETE:
 *      Template is incomplete or invalid.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The buffer for an attribute is too small, attribute's value is updated
 *      with the expected value.
 *  - CKR_ATTRIBUTE_TYPE_INVALID:
 *      Attribute type is invalid.
 *  - CKR_ATTRIBUTE_SENSITIVE:
 *      Attribute is sensitive or unextractable.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
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

/**
 * C_SetAttributeValue() - Modify the value of one or more attributes of an
 *                         object.
 * @hSession: [in] Session handle.
 * @hObject: [in] Handle of the object.
 * @pTemplate: [in] Pointer to template that specifies which attributes to
 *                  modify.
 * @ulCount: [in] Number of attributes in the template.
 *
 * The function modifies the value of one or more attributes of an object.
 *
 * If an object can not be modified, the function returns with
 * CKR_ACTION_PROHIBITED. The application can consult the object's
 * CKA_MODIFIABLE attribute to determine if modification is allowed.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @hObject is NULL.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is not valid.
 *  - CKR_TEMPLATE_INCOMPLETE:
 *      Template is incomplete or invalid.
 *  - CKR_ATTRIBUTE_TYPE_INVALID:
 *      Attribute type is invalid.
 *  - CKR_ATTRIBUTE_VALUE_INVALID:
 *      Attribute `pValue` is NULL.
 *  - CKR_ATTRIBUTE_READ_ONLY:
 *      Attribute is read-only.
 *  - CKR_ACTION_PROHIBITED:
 *      Object can not be modified.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
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

/**
 * C_FindObjectsInit() - Initialize a search for token and session objects.
 * @hSession: [in] Session handle.
 * @pTemplate: [in] Pointer to search template that specifies the attribute
 *                  values to match.
 * @ulCount: [in] Number of attributes in the search template.
 *
 * The function initializes a search for token and session objects that match
 * the input @pTemplate. After calling C_FindObjectsInit(), the application may
 * call C_FindObjects() one or more times to obtain handles for objects matching
 * the template, and then eventually call C_FindObjectsFinal() to finish the
 * active search operation.
 *
 * Passing the @ulCount as 0 will match all objects.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pTemplate is NULL and @ulCount is not 0.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is not valid.
 *  - CKR_ATTRIBUTE_TYPE_INVALID:
 *      Attribute type is invalid.
 *  - CKR_ATTRIBUTE_VALUE_INVALID:
 *      Attribute value is invalid.
 *  - CKR_OPERATION_ACTIVE:
 *      Find operation is already active. The C_FindObjectsFinal() must be
 *      called to start a new search.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	/* ulCount=0 is valid and will find all objects */
	if (!pTemplate && ulCount)
		return CKR_ARGUMENTS_BAD;

	return libobj_find_init(hSession, pTemplate, ulCount);
}

/**
 * C_FindObjects() - Continue a search for token and session objects.
 * @hSession: [in] Session handle.
 * @phObject: [out] Pointer to location that receives the list of object handles.
 * @ulMaxObjectCount: [in] Maximum number of object handles to be returned.
 * @pulObjectCount: [out] Pointer to location that receives the actual number
 *                        of object handles returned.
 *
 * The function returns the object handles matching the template specified
 * during the C_FindObjectsInit() initialization function.
 *
 * If there is no more objects to find, the function returns CKR_OK and sets
 * @pulObjectCount to 0.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @phObject is NULL.
 *      The @phulObjectCount is NULL.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is not valid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
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

/**
 * C_FindObjectsFinal() - Finish a search for token and session objects.
 * @hSession: [in] Session handle.
 *
 * The function finishes a search for token and session objects.
 *
 * Return:
 * CKR_SESSION_HANDLE_INVALID	- Session handle is not valid.
 * CKR_OK			- Success.
 * Others			- Error from libobj_find_final().
 */
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return libobj_find_final(hSession);
}
