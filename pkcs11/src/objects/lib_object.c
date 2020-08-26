// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdlib.h>

#include "attributes.h"
#include "key.h"

#include "lib_object.h"
#include "lib_session.h"
#include "util.h"

#include "trace.h"

#define OBJ_RO	    BIT(0)
#define OBJ_RW	    BIT(1)
#define OBJ_PUBLIC  BIT(4)
#define OBJ_PRIVATE BIT(5)

enum attr_obj_common_list {
	OBJ_CLASS = 0,
};

const struct template_attr attr_obj_common[] = {
	[OBJ_CLASS] = { CKA_CLASS, sizeof(CK_OBJECT_CLASS), MUST,
			attr_to_class },
};

enum attr_obj_storage_list {
	STORAGE_TOKEN = 0,
	STORAGE_PRIVATE,
	STORAGE_MODIFIABLE,
	STORAGE_COPYABLE,
	STORAGE_DESTROYABLE,
	STORAGE_LABEL,
	STORAGE_UNIQUE_ID,
};

const struct template_attr attr_obj_storage[] = {
	[STORAGE_TOKEN] = { CKA_TOKEN, sizeof(CK_BBOOL), OPTIONAL,
			    attr_to_bool },
	[STORAGE_PRIVATE] = { CKA_PRIVATE, sizeof(CK_BBOOL), OPTIONAL,
			      attr_to_bool },
	[STORAGE_MODIFIABLE] = { CKA_MODIFIABLE, sizeof(CK_BBOOL), OPTIONAL,
				 attr_to_bool },
	[STORAGE_COPYABLE] = { CKA_COPYABLE, sizeof(CK_BBOOL), OPTIONAL,
			       attr_to_bool },
	[STORAGE_DESTROYABLE] = { CKA_DESTROYABLE, sizeof(CK_BBOOL), OPTIONAL,
				  attr_to_bool },
	[STORAGE_LABEL] = { CKA_LABEL, 0, OPTIONAL, attr_to_rfc2279 },
	[STORAGE_UNIQUE_ID] = { CKA_UNIQUE_ID, 0, READ_ONLY, attr_to_rfc2279 },
};

struct libobj_storage {
	bool token;
	bool private;
	bool modifiable;
	bool copyable;
	bool destroyable;
	struct rfc2279 label;
	struct rfc2279 unique_id;
	void *subobject;
};

/**
 * get_session_obj_access() - Get the session object right access
 * @hsession: Session Handle
 * @access: Session object right access
 *
 * Function of the session and login, get the session object right access
 * to ensure that session object can be handled.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Success
 */
static CK_RV get_session_obj_access(CK_SESSION_HANDLE hsession,
				    unsigned int *access)
{
	CK_RV ret;
	CK_SESSION_INFO sinfo;

	ret = libsess_get_info(hsession, &sinfo);
	if (ret != CKR_OK)
		return ret;

	/* Default session object access */
	*access = OBJ_RW | OBJ_PUBLIC;
	if (sinfo.state == CKS_RW_USER_FUNCTIONS ||
	    sinfo.state == CKS_RO_USER_FUNCTIONS)
		*access |= OBJ_PRIVATE;

	return CKR_OK;
}

/**
 * get_token_obj_access() - Get the token object right access
 * @hsession: Session Handle
 * @access: Token object right access
 *
 * Function of the session and login, get the token object right access
 * to ensure that token object can be handled.
 * An object is a token object if CKA_TOKEN attribute is true.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Success
 */
static CK_RV get_token_obj_access(CK_SESSION_HANDLE hsession,
				  unsigned int *access)
{
	CK_RV ret;
	CK_SESSION_INFO sinfo;

	ret = libsess_get_info(hsession, &sinfo);
	if (ret != CKR_OK)
		return ret;

	/* Default token object access */
	*access = OBJ_RO | OBJ_PUBLIC;
	if (sinfo.state == CKS_RW_PUBLIC_SESSION ||
	    sinfo.state == CKS_RW_USER_FUNCTIONS ||
	    sinfo.state == CKS_RW_SO_FUNCTIONS)
		*access |= OBJ_RW;

	if (sinfo.state == CKS_RO_USER_FUNCTIONS ||
	    sinfo.state == CKS_RW_USER_FUNCTIONS)
		*access |= OBJ_PRIVATE;

	return CKR_OK;
}

/**
 * obj_is_destroyable() - Return if an object is destroyable
 * @hsession: Session handle
 * @obj: Object
 *
 * return:
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_ACTION_PROHIBITED         - Object is not destroyable
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Success
 */
static CK_RV obj_is_destoyable(CK_SESSION_HANDLE hsession, struct libobj *obj)
{
	CK_RV ret;
	unsigned int access;
	bool is_destroyable = true;
	bool is_private = false;

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		is_destroyable = ((struct libobj_storage *)obj)->destroyable;
		is_private = ((struct libobj_storage *)obj)->private;
		DBG_TRACE("Storage object class %lu, destroy=%d, private=%d",
			  obj->class, is_destroyable, is_private);
		break;

	default:
		return CKR_FUNCTION_FAILED;
	}

	if (!is_destroyable)
		return CKR_ACTION_PROHIBITED;

	ret = get_session_obj_access(hsession, &access);
	if (ret != CKR_OK)
		return ret;

	if (is_private && !(access & OBJ_PRIVATE))
		return CKR_ACTION_PROHIBITED;

	return CKR_OK;
}

/**
 * obj_allocate() - Allocate and initialize common object
 * @obj: Object allocated
 *
 * return:
 * CKR_HOST_MEMORY - Out of memory
 * CKR_OK          - Success
 */
static CK_RV obj_allocate(struct libobj **obj)
{
	struct libobj *newobj;

	newobj = malloc(sizeof(*newobj));
	if (!newobj)
		return CKR_HOST_MEMORY;

	newobj->class = 0;
	newobj->object = NULL;
	newobj->prev = NULL;
	newobj->next = NULL;

	*obj = newobj;

	DBG_TRACE("Allocated a new object (%p)", *obj);

	return CKR_OK;
}

/**
 * obj_storage_allocate() - Allocate and initialize storage object
 * @obj: Object allocated
 *
 * return:
 * CKR_HOST_MEMORY - Out of memory
 * CKR_OK          - Success
 */
static CK_RV obj_storage_allocate(struct libobj_storage **obj)
{
	struct libobj_storage *newobj;

	newobj = malloc(sizeof(*newobj));
	if (!newobj)
		return CKR_HOST_MEMORY;

	/*
	 * Initialize object default value in case not present
	 * in the attribute list.
	 */
	newobj->token = false;
	newobj->private = false;
	newobj->modifiable = true;
	newobj->copyable = true;
	newobj->destroyable = true;
	newobj->label.string = NULL;
	newobj->label.length = 0;
	newobj->unique_id.string = NULL;
	newobj->unique_id.length = 0;
	newobj->subobject = NULL;

	*obj = newobj;

	DBG_TRACE("Allocated a new storage object (%p)", *obj);

	return CKR_OK;
}

/**
 * obj_storage_free() - Free a storage object type
 * @obj - Object containing the storage object
 */
static void obj_storage_free(struct libobj *obj)
{
	struct libobj_storage *objstorage;

	if (!obj)
		return;

	objstorage = obj->object;
	if (!objstorage)
		return;

	DBG_TRACE("Free storage object (%p)", objstorage);

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		key_free(objstorage->subobject, obj->class);
		break;

	default:
		DBG_TRACE("Class object %lu not supported", obj->class);
		break;
	}

	if (objstorage->label.string)
		free(objstorage->label.string);

	if (objstorage->unique_id.string)
		free(objstorage->unique_id.string);

	free(objstorage);
}

/**
 * obj_free() - Free an object
 * @obj: Object to free
 *
 * Function the object class call class's object free function.
 */
static void obj_free(struct libobj *obj)
{
	if (!obj)
		return;

	DBG_TRACE("Free object (%p)", obj);

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		obj_storage_free(obj);
		break;

	default:
		break;
	}

	free(obj);
}

/**
 * obj_storage_new() - Create a new storage object type
 * @hsession: Session handle
 * @obj: Object into which storage object is to be attached
 * @attrs: List of object attributes
 *
 * Allocates a new storage object and setup the common storage
 * attributes function of @attrs given list.
 * Then function of object class and session/token access right calls
 * function to create subobject.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_USER_NOT_LOGGED_IN        - User must be login to create object
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTIBUTE_VALUE_INVALID    - Attribute length is not valid
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
static CK_RV obj_storage_new(CK_SESSION_HANDLE hsession, struct libobj *obj,
			     struct libattr_list *attrs)
{
	CK_RV ret;
	unsigned int access;
	struct libobj_storage *newobj = NULL;

	ret = obj_storage_allocate(&newobj);
	if (ret != CKR_OK)
		return ret;

	obj->object = newobj;

	DBG_TRACE("Create a new storage object (%p)", newobj);

	ret = attr_get_value(&newobj->token, &attr_obj_storage[STORAGE_TOKEN],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	/* TODO: Support Token object */
	if (newobj->token)
		return CKR_FUNCTION_FAILED;

	ret = attr_get_value(&newobj->private,
			     &attr_obj_storage[STORAGE_PRIVATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&newobj->modifiable,
			     &attr_obj_storage[STORAGE_MODIFIABLE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&newobj->copyable,
			     &attr_obj_storage[STORAGE_COPYABLE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&newobj->destroyable,
			     &attr_obj_storage[STORAGE_DESTROYABLE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&newobj->label, &attr_obj_storage[STORAGE_LABEL],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&newobj->unique_id,
			     &attr_obj_storage[STORAGE_UNIQUE_ID], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	if (newobj->token)
		ret = get_token_obj_access(hsession, &access);
	else
		ret = get_session_obj_access(hsession, &access);

	if (ret != CKR_OK)
		return ret;

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
		if (!(access & OBJ_PRIVATE))
			return CKR_USER_NOT_LOGGED_IN;

		/* This is a private object anyway */
		newobj->private = true;
		__attribute__((fallthrough));

	case CKO_PUBLIC_KEY:
		ret = key_create(&newobj->subobject, obj->class, attrs);
		if (ret != CKR_OK)
			return ret;
		break;

	default:
		DBG_TRACE("Class object %lu not supported", obj->class);
		return CKR_FUNCTION_FAILED;
	}

	if (!newobj->token) {
		ret = libsess_add_object(hsession, obj);
		DBG_TRACE("Add object to the session object list return %ld",
			  ret);
	}

	return ret;
}

CK_RV libobj_create(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		    CK_ULONG nb_attrs, CK_OBJECT_HANDLE_PTR hobj)
{
	CK_RV ret;
	struct libobj *newobj = NULL;
	struct libattr_list attrs_list = { .attr = attrs, .number = nb_attrs };

	DBG_TRACE("Create an object on session %lu", hsession);

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		goto end;

	ret = obj_allocate(&newobj);
	if (ret != CKR_OK)
		goto end;

	DBG_TRACE("Create a new object (%p)", newobj);

	/* Get the class of the object */
	ret = attr_get_value(&newobj->class, &attr_obj_common[OBJ_CLASS],
			     &attrs_list, NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	switch (newobj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		ret = obj_storage_new(hsession, newobj, &attrs_list);
		break;

	default:
		DBG_TRACE("Class object %lu not supported", newobj->class);
		ret = CKR_FUNCTION_FAILED;
		break;
	}

end:
	DBG_TRACE("Object (%p) creation return %ld", newobj, ret);

	if (ret == CKR_OK)
		*hobj = (CK_OBJECT_HANDLE)newobj;
	else
		obj_free(newobj);

	return ret;
}

void libobj_delete(struct libobj *object)
{
	DBG_TRACE("Destroy object (%p)", object);
	obj_free(object);
}

CK_RV libobj_destroy(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE hobject)
{
	CK_RV ret;
	struct libobj *object = (struct libobj *)hobject;

	DBG_TRACE("Destroy object (%p) of session %lu", object, hsession);

	ret = libsess_find_object(hsession, object);
	if (ret != CKR_OK)
		goto end;

	/* Check if the object can be destroyed */
	ret = obj_is_destoyable(hsession, object);
	if (ret != CKR_OK)
		goto end;

	ret = libsess_remove_object(hsession, object);
	if (ret == CKR_OK)
		obj_free(object);

end:
	DBG_TRACE("Destroy object (%p) return %lu", object, ret);
	return ret;
}