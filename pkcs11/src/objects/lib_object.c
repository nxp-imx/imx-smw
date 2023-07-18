// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "attributes.h"
#include "data.h"
#include "key.h"

#include "lib_mutex.h"
#include "lib_object.h"
#include "lib_session.h"
#include "libobj_types.h"
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
	[OBJ_CLASS] =
		TATTR(obj, class, CLASS, sizeof(CK_OBJECT_CLASS), MUST, class),
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
	[STORAGE_TOKEN] = TATTR(storage, token, TOKEN, sizeof(CK_BBOOL),
				OPTIONAL, boolean),
	[STORAGE_PRIVATE] = TATTR(storage, private, PRIVATE, sizeof(CK_BBOOL),
				  OPTIONAL, boolean),
	[STORAGE_MODIFIABLE] = TATTR(storage, modifiable, MODIFIABLE,
				     sizeof(CK_BBOOL), OPTIONAL, boolean),
	[STORAGE_COPYABLE] =
		TATTR_MS(storage, copyable, COPYABLE, sizeof(CK_BBOOL),
			 OPTIONAL, boolean, false_only),
	[STORAGE_DESTROYABLE] = TATTR(storage, destroyable, DESTROYABLE,
				      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[STORAGE_LABEL] = TATTR_M(storage, label, LABEL, 0, OPTIONAL, rfc2279),
	[STORAGE_UNIQUE_ID] =
		TATTR(storage, unique_id, UNIQUE_ID, 0, READ_ONLY, rfc2279),
};

/**
 * obj_add_to_list() - Add @obj to session or token objects list
 * @hsession: Session handle
 * @obj: Object to add
 * @token: True if token object
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
static CK_RV obj_add_to_list(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			     bool token)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libobj_list *objects = NULL;

	DBG_TRACE("Add object (%p) in session %lu list", obj, hsession);

	if (token) {
		ret = libsess_get_device(hsession, &dev);
		if (ret != CKR_OK)
			return ret;

		objects = &dev->objects;
	} else {
		ret = libsess_get_objects(hsession, &objects);
		if (ret != CKR_OK)
			return ret;
	}

	ret = LLIST_INSERT_TAIL(objects, obj);

	return ret;
}

/**
 * find_lock_object() - Find and lock a token or session object
 * @hsession: Session Handle
 * @obj: Object to find
 * @list: Output of the object's list (session or token)
 *
 * Try to find the object by handle in first the token object lists,
 * then in the session object lists.
 * If object is found, it's locked.
 * IF parameter @list is not NULL, the function return the pointer
 * to the list where object is present.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OBJECT_HANDLE_INVALID          - Object not found
 * CKR_MUTEX_BAD                      - Mutex not correct
 * CKR_HOST_MEMORY                    - Memory error
 * CKR_OK                             - Success
 */
static CK_RV find_lock_object(CK_SESSION_HANDLE hsession,
			      struct libobj_obj *obj, struct libobj_list **list)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libobj_list *objects = NULL;
	struct libobj_obj *fobj = NULL;

	DBG_TRACE("Find and lock object %p", obj);

	ret = libsess_get_device(hsession, &dev);
	if (ret != CKR_OK)
		return ret;

	/* Try to find the object in the token list */
	objects = &dev->objects;
	ret = LLIST_LOCK(objects);
	if (ret != CKR_OK)
		return ret;

	LIST_FIND(fobj, objects, obj);
	if (fobj == obj)
		ret = libmutex_lock(obj->lock);

	LLIST_UNLOCK(objects);

	if (fobj != obj) {
		DBG_TRACE("Object %p NOT in token list", obj);

		/*
		 * Object is not in the token list.
		 * Try the session object list.
		 */
		ret = libsess_get_objects(hsession, &objects);
		if (ret != CKR_OK)
			return ret;

		ret = LLIST_LOCK(objects);
		if (ret != CKR_OK)
			return ret;

		LIST_FIND(fobj, objects, obj);
		if (fobj == obj)
			ret = libmutex_lock(obj->lock);

		LLIST_UNLOCK(objects);

		if (fobj != obj) {
			DBG_TRACE("Object %p NOT in session list", obj);
			return CKR_OBJECT_HANDLE_INVALID;
		}
	}

	if (ret == CKR_OK) {
		DBG_TRACE("Object %p found in list %p", obj, objects);
		if (list)
			*list = objects;
	}

	// coverity[missing_unlock]
	return ret;
}

/**
 * set_unique_id() - Set the object unique id
 * @obj: object
 *
 * Build and return the object unique id with the object class
 * and SMW returned ID.
 *
 * return:
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV set_unique_id(struct libobj_obj *obj)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct librfc2279 *unique_id = NULL;
	struct libbytes id = { 0 };

	if (!obj)
		return ret;

	DBG_TRACE("Class %lx", obj->class);

	switch (obj->class) {
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		unique_id = get_unique_id_obj(obj, storage);
		ret = key_get_id(&id, obj, sizeof(obj->class));
		break;

	default:
		return CKR_FUNCTION_FAILED;
	}

	if (ret != CKR_OK)
		goto end;

	TO_CK_BYTES(id.array, obj->class);

	/* Get UTF8 length and allocate UTF8 string */
	unique_id->length = util_byte_to_utf8_len(id.array, id.number);
	if (!unique_id->length) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	unique_id->string = malloc(unique_id->length);
	if (!unique_id->string) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	ret = CKR_FUNCTION_FAILED;
	if (util_byte_to_utf8(unique_id->string, unique_id->length, id.array,
			      id.number) == id.number)
		ret = CKR_OK;

end:
	if (id.array)
		free(id.array);

	if (ret != CKR_OK && unique_id->string) {
		free(unique_id->string);
		unique_id->string = NULL;
		unique_id->length = 0;
	}

	return ret;
}

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
	CK_RV ret = CKR_OK;
	CK_SESSION_INFO sinfo = { 0 };

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
	CK_RV ret = CKR_OK;
	CK_SESSION_INFO sinfo = { 0 };

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
static CK_RV obj_is_destroyable(CK_SESSION_HANDLE hsession,
				struct libobj_obj *obj)
{
	CK_RV ret = CKR_FUNCTION_FAILED;
	unsigned int access = OBJ_RO;
	bool is_destroyable = false;
	bool is_private = false;

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_DATA:
		is_destroyable = is_destroyable_obj(obj, storage);
		is_private = is_private_obj(obj, storage);
		DBG_TRACE("Storage object class %lu, destroy=%d, private=%d",
			  obj->class, is_destroyable, is_private);
		break;

	default:
		return ret;
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
 * obj_is_modifiable() - Return if an object is modifiable
 * @hsession: Session handle
 * @obj: Object
 *
 * return:
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_ACTION_PROHIBITED         - Object is not modifiable
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Object is modifiable
 */
static CK_RV obj_is_modifiable(CK_SESSION_HANDLE hsession,
			       struct libobj_obj *obj)
{
	CK_RV ret = CKR_FUNCTION_FAILED;
	unsigned int access = OBJ_RO;
	bool is_modifiable = false;
	bool is_token = false;

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		is_modifiable = is_modifiable_obj(obj, storage);
		is_token = is_token_obj(obj, storage);
		DBG_TRACE("Storage object class %lu, modifiable=%d, token=%d",
			  obj->class, is_modifiable, is_token);
		break;

	default:
		return ret;
	}

	if (!is_modifiable)
		return CKR_ACTION_PROHIBITED;

	/* Token objects can be modifiable only if R/W Session */
	if (is_token) {
		ret = get_token_obj_access(hsession, &access);
		if (ret != CKR_OK)
			return ret;

		if (!(access & OBJ_RW))
			return CKR_ACTION_PROHIBITED;
	}

	return CKR_OK;
}

/**
 * obj_allocate() - Allocate and initialize common object
 * @obj: Object allocated
 *
 * return:
 * CKR_GENERAL_ERROR - No context available
 * CKR_HOST_MEMORY   - Out of memory
 * CKR_OK            - Success
 */
static CK_RV obj_allocate(struct libobj_obj **obj)
{
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_obj *newobj = NULL;

	newobj = malloc(sizeof(*newobj));
	if (!newobj)
		goto end;

	ret = libmutex_create(&newobj->lock);
	if (ret != CKR_OK)
		goto end;

	newobj->class = 0;
	newobj->object = NULL;
	newobj->prev = NULL;
	newobj->next = NULL;

end:
	if (ret != CKR_OK) {
		free(newobj);
		newobj = NULL;
	}

	*obj = newobj;

	DBG_TRACE("Allocated a new object (%p)", *obj);

	return ret;
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
	struct libobj_storage *newobj = NULL;

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
static void obj_storage_free(struct libobj_obj *obj)
{
	struct libobj_storage *objstorage = NULL;

	if (!obj)
		return;

	objstorage = get_object_from(obj);
	if (!objstorage)
		return;

	DBG_TRACE("Free storage object (%p)", objstorage);

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		key_free(obj);
		break;

	case CKO_DATA:
		data_free(obj);
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
 * @list: List of objects
 *
 * Function the object class call class's object free function.
 */
static void obj_free(struct libobj_obj *obj, struct libobj_list *list)
{
	if (!obj)
		return;

	DBG_TRACE("Free object (%p)", obj);

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_DATA:
		obj_storage_free(obj);
		break;

	default:
		break;
	}

	if (list) {
		DBG_TRACE("Remove object (%p) from %p", obj, list);
		LIST_REMOVE(list, obj);
	}

	libmutex_unlock(obj->lock);
	libmutex_destroy(obj->lock);

	free(obj);
}

/**
 * obj_storage_new() - New storage object type
 * @hsession: Session handle
 * @obj: Object into which storage object is to be attached
 * @attrs: List of object attributes
 *
 * Allocates a new storage object and setup the common storage
 * attributes function of @attrs given list.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_USER_NOT_LOGGED_IN        - User must be login to create object
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute length is not valid
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
static CK_RV obj_storage_new(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			     struct libattr_list *attrs)
{
	CK_RV ret = CKR_OK;
	unsigned int access = OBJ_RO;
	struct libobj_storage *newobj = NULL;

	ret = obj_storage_allocate(&newobj);
	if (ret != CKR_OK)
		return ret;

	obj->object = newobj;

	DBG_TRACE("New storage object (%p)", newobj);

	ret = attr_get_value(newobj, &attr_obj_storage[STORAGE_TOKEN], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(newobj, &attr_obj_storage[STORAGE_PRIVATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(newobj, &attr_obj_storage[STORAGE_MODIFIABLE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(newobj, &attr_obj_storage[STORAGE_COPYABLE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(newobj, &attr_obj_storage[STORAGE_DESTROYABLE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(newobj, &attr_obj_storage[STORAGE_LABEL], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(newobj, &attr_obj_storage[STORAGE_UNIQUE_ID],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	if (newobj->token)
		ret = get_token_obj_access(hsession, &access);
	else
		ret = get_session_obj_access(hsession, &access);

	if (ret != CKR_OK)
		return ret;

	if (obj->class == CKO_PRIVATE_KEY || obj->class == CKO_SECRET_KEY) {
		if (!(access & OBJ_PRIVATE))
			return CKR_USER_NOT_LOGGED_IN;

		/* This is a private object anyway */
		newobj->private = true;
	}

	return CKR_OK;
}

/**
 * class_get_attribute() - Get an attribute from the class object
 * @attr: Attribute to get
 * @libobj: Library object reference
 *
 * Get the given attribute @attr from the object's class,
 * if not present, call the class's subobject get attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV class_get_attribute(CK_ATTRIBUTE_PTR attr,
				 const struct libobj_obj *libobj)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	DBG_TRACE("Get attribute type=%#lx", attr->type);
	switch (libobj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		ret = attr_get_obj_value(attr, attr_obj_storage,
					 ARRAY_SIZE(attr_obj_storage),
					 get_object_from(libobj));
		/*
		 * If attribute not present in the common storage
		 * object attributes, try to get it from
		 * the specific key object
		 */
		if (ret == CKR_ATTRIBUTE_TYPE_INVALID)
			ret = key_get_attribute(attr, libobj);

		break;

	case CKO_DATA:
		ret = attr_get_obj_value(attr, attr_obj_storage,
					 ARRAY_SIZE(attr_obj_storage),
					 get_object_from(libobj));
		/*
		 * If attribute not present in the common storage
		 * object attributes, try to get it from
		 * the specific data object
		 */
		if (ret == CKR_ATTRIBUTE_TYPE_INVALID)
			ret = data_get_attribute(attr, libobj);

		break;

	default:
		break;
	}

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

/**
 * class_modify_attribute() - Modify an attribute of the class object
 * @attr: Attribute to modify
 * @libobj: Library object reference
 *
 * Modify the given attribute @attr of the object's class,
 * if not present, call the class's subobject modify attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value or length not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV class_modify_attribute(CK_ATTRIBUTE_PTR attr,
				    struct libobj_obj *libobj)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);
	switch (libobj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		ret = attr_modify_obj_value(attr, attr_obj_storage,
					    ARRAY_SIZE(attr_obj_storage),
					    get_object_from(libobj));
		/*
		 * If attribute not present in the common storage
		 * object attributes, try to modify it in
		 * the specific key object
		 */
		if (ret == CKR_ATTRIBUTE_TYPE_INVALID)
			ret = key_modify_attribute(attr, libobj);

		break;

	case CKO_DATA:
		ret = attr_modify_obj_value(attr, attr_obj_storage,
					    ARRAY_SIZE(attr_obj_storage),
					    get_object_from(libobj));
		/*
		 * If attribute not present in the common storage
		 * object attributes, try to modify it in
		 * the specific data object
		 */
		if (ret == CKR_ATTRIBUTE_TYPE_INVALID)
			ret = data_modify_attribute(attr, libobj);

		break;

	default:
		break;
	}

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV libobj_create(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		    CK_ULONG nb_attrs, CK_OBJECT_HANDLE_PTR hobj)
{
	CK_RV ret = CKR_OK;
	struct libobj_obj *newobj = NULL;
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
	ret = attr_get_value(newobj, &attr_obj_common[OBJ_CLASS], &attrs_list,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	switch (newobj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
		ret = obj_storage_new(hsession, newobj, &attrs_list);
		if (ret != CKR_OK)
			break;

		ret = key_create(hsession, newobj, &attrs_list);
		break;

	case CKO_DATA:
		ret = obj_storage_new(hsession, newobj, &attrs_list);
		if (ret != CKR_OK)
			break;

		ret = data_create(hsession, newobj, &attrs_list);
		break;

	default:
		DBG_TRACE("Class object %lu not supported", newobj->class);
		ret = CKR_FUNCTION_FAILED;
		break;
	}

	if (ret == CKR_OK)
		ret = obj_add_to_list(hsession, newobj,
				      is_token_obj(newobj, storage));

end:
	DBG_TRACE("Object (%p) creation return %ld", newobj, ret);

	if (ret == CKR_OK)
		*hobj = (CK_OBJECT_HANDLE)newobj;
	else
		obj_free(newobj, NULL);

	return ret;
}

CK_RV libobj_destroy(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE hobject)
{
	CK_RV ret = CKR_OK;
	struct libobj_obj *obj = (struct libobj_obj *)hobject;
	struct libobj_list *objects = NULL;

	DBG_TRACE("Destroy object (%p) of session %lu", obj, hsession);

	ret = find_lock_object(hsession, obj, &objects);
	if (ret == CKR_OK) {
		/* Check if the object can be destroyed */
		ret = obj_is_destroyable(hsession, obj);
		if (ret == CKR_OK) {
			obj_free(obj, objects);
			obj = NULL;
		} else {
			libmutex_unlock(obj->lock);
		}
	}

	DBG_TRACE("Destroy object (%p) return %lu", obj, ret);
	return ret;
}

CK_RV libobj_get_attribute(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE hobject,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG nb_attrs)
{
	CK_RV ret = CKR_OK;
	CK_RV status = CKR_OK;
	struct libobj_obj *libobj = (struct libobj_obj *)hobject;
	CK_ULONG idx = 0;

	DBG_TRACE("Get attribute(s) of object (%p) in session %lu", libobj,
		  hsession);

	ret = find_lock_object(hsession, libobj, NULL);
	if (ret != CKR_OK)
		goto end;

	DBG_TRACE("Get %lu attribute(s)", nb_attrs);
	for (; idx < nb_attrs; idx++) {
		DBG_TRACE("Get attribute %lu type=%#lx", idx, attrs[idx].type);
		status =
			attr_get_obj_value(&attrs[idx], attr_obj_common,
					   ARRAY_SIZE(attr_obj_common), libobj);
		if (status == CKR_ATTRIBUTE_TYPE_INVALID) {
			/*
			 * Attribute not present in the common
			 * object attributes, try to get it from
			 * the specific class object
			 */
			status = class_get_attribute(&attrs[idx], libobj);
		}

		DBG_TRACE("Get attribute %lu type=%#lx status=%ld", idx,
			  attrs[idx].type, status);
		/*
		 * Continue to parse all requested attributes while
		 * there is not fatal error, else return the fatal error
		 * immediately.
		 * If status is not CKR_OK, set return function  value
		 * to the first error occurring.
		 */
		if (status != CKR_OK && status != CKR_ATTRIBUTE_TYPE_INVALID &&
		    status != CKR_BUFFER_TOO_SMALL &&
		    status != CKR_ATTRIBUTE_SENSITIVE) {
			ret = status;
			break;
		}

		if (ret == CKR_OK && status != CKR_OK)
			ret = status;
	}

	libmutex_unlock(libobj->lock);

end:
	DBG_TRACE("Get attribute(s) of object (%p) return %lu", libobj, ret);
	return ret;
}

CK_RV libobj_modify_attribute(CK_SESSION_HANDLE hsession,
			      CK_OBJECT_HANDLE hobject, CK_ATTRIBUTE_PTR attrs,
			      CK_ULONG nb_attrs)
{
	CK_RV ret = CKR_OK;
	struct libobj_obj *libobj = (struct libobj_obj *)hobject;
	CK_ULONG idx = 0;

	DBG_TRACE("Modify attribute(s) of object (%p) in session %lu", libobj,
		  hsession);

	ret = find_lock_object(hsession, libobj, NULL);
	if (ret != CKR_OK)
		goto end;

	ret = obj_is_modifiable(hsession, libobj);

	DBG_TRACE("Modify %lu attribute(s)", nb_attrs);
	for (; idx < nb_attrs && ret == CKR_OK; idx++) {
		DBG_TRACE("Modify attribute %lu type=%#lx", idx,
			  attrs[idx].type);
		ret = attr_modify_obj_value(&attrs[idx], attr_obj_common,
					    ARRAY_SIZE(attr_obj_common),
					    libobj);
		/*
		 * If attribute not present in the common
		 * object attributes, try to modify it from
		 * the specific class object
		 */
		if (ret == CKR_ATTRIBUTE_TYPE_INVALID)
			ret = class_modify_attribute(&attrs[idx], libobj);

		DBG_TRACE("Modify attribute %lu type=%#lx status=%ld", idx,
			  attrs[idx].type, ret);
	}

	libmutex_unlock(libobj->lock);

end:
	DBG_TRACE("Modify attribute(s) of object (%p) return %lu", libobj, ret);
	return ret;
}

CK_RV libobj_generate_keypair(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      CK_ATTRIBUTE_PTR pub_attrs, CK_ULONG nb_pub_attrs,
			      CK_ATTRIBUTE_PTR priv_attrs,
			      CK_ULONG nb_priv_attrs, CK_OBJECT_HANDLE_PTR hpub,
			      CK_OBJECT_HANDLE_PTR hpriv)
{
	CK_RV ret = CKR_OK;
	struct libobj_obj *pub_key = NULL;
	struct libobj_obj *priv_key = NULL;
	struct libattr_list pub_attrs_list = { .attr = pub_attrs,
					       .number = nb_pub_attrs };
	struct libattr_list priv_attrs_list = { .attr = priv_attrs,
						.number = nb_priv_attrs };

	DBG_TRACE("Generate a keypair on session %lu", hsession);

	ret = libsess_validate_mechanism(hsession, mech, CKF_GENERATE_KEY_PAIR);
	if (ret != CKR_OK)
		goto end;

	/*
	 * First create the storage object for the public key
	 */
	ret = obj_allocate(&pub_key);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Get the optional class of the object
	 * By default this is a CKO_PUBLIC_KEY class
	 */
	pub_key->class = CKO_PUBLIC_KEY;
	ret = attr_get_value(pub_key, &attr_obj_common[OBJ_CLASS],
			     &pub_attrs_list, OPTIONAL);
	if (ret != CKR_OK)
		goto end;

	if (pub_key->class != CKO_PUBLIC_KEY) {
		ret = CKR_TEMPLATE_INCONSISTENT;
		goto end;
	}

	ret = obj_storage_new(hsession, pub_key, &pub_attrs_list);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Next create the storage object for the private key
	 */
	ret = obj_allocate(&priv_key);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Get the optional class of the object
	 * By default this is a CKO_PRIVATE_KEY class
	 */
	priv_key->class = CKO_PRIVATE_KEY;
	ret = attr_get_value(priv_key, &attr_obj_common[OBJ_CLASS],
			     &priv_attrs_list, OPTIONAL);
	if (ret != CKR_OK)
		goto end;

	if (priv_key->class != CKO_PRIVATE_KEY) {
		ret = CKR_TEMPLATE_INCONSISTENT;
		goto end;
	}

	ret = obj_storage_new(hsession, priv_key, &priv_attrs_list);
	if (ret != CKR_OK)
		goto end;

	/*
	 * If either public or private key is a token object,
	 * align both objects as token objects
	 */
	if (is_token_obj(pub_key, storage) || is_token_obj(priv_key, storage)) {
		set_token_obj(pub_key, storage);
		set_token_obj(priv_key, storage);
	}

	ret = key_keypair_generate(hsession, mech, pub_key, &pub_attrs_list,
				   priv_key, &priv_attrs_list);
	if (ret == CKR_OK) {
		ret = set_unique_id(pub_key);
		if (ret == CKR_OK)
			ret = set_unique_id(priv_key);
	}

	if (ret != CKR_OK)
		goto end;

	ret = obj_add_to_list(hsession, pub_key,
			      is_token_obj(pub_key, storage));
	if (ret == CKR_OK) {
		ret = obj_add_to_list(hsession, priv_key,
				      is_token_obj(priv_key, storage));
	}

end:
	DBG_TRACE("Generate keypair return %ld", ret);

	if (ret == CKR_OK) {
		*hpub = (CK_OBJECT_HANDLE)pub_key;
		*hpriv = (CK_OBJECT_HANDLE)priv_key;
	} else {
		obj_free(pub_key, NULL);
		obj_free(priv_key, NULL);
	}

	return ret;
}

CK_RV libobj_generate_key(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			  CK_ATTRIBUTE_PTR attrs, CK_ULONG nb_attrs,
			  CK_OBJECT_HANDLE_PTR hkey)
{
	CK_RV ret = CKR_OK;
	struct libobj_obj *key = NULL;
	struct libattr_list attrs_list = { .attr = attrs, .number = nb_attrs };

	DBG_TRACE("Generate a secret key on session %lu", hsession);

	ret = libsess_validate_mechanism(hsession, mech, CKF_GENERATE);
	if (ret != CKR_OK)
		goto end;

	/*
	 * First create the storage object for the secret key
	 */
	ret = obj_allocate(&key);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Get the optional class of the object
	 * By default this is a CKO_SECRET_KEY class
	 */
	key->class = CKO_SECRET_KEY;
	ret = attr_get_value(key, &attr_obj_common[OBJ_CLASS], &attrs_list,
			     OPTIONAL);
	if (ret != CKR_OK)
		goto end;

	if (key->class != CKO_SECRET_KEY) {
		ret = CKR_TEMPLATE_INCONSISTENT;
		goto end;
	}

	ret = obj_storage_new(hsession, key, &attrs_list);
	if (ret != CKR_OK)
		goto end;

	ret = key_secret_key_generate(hsession, mech, key, &attrs_list);

	if (ret == CKR_OK)
		ret = set_unique_id(key);

	if (ret == CKR_OK)
		ret = obj_add_to_list(hsession, key,
				      is_token_obj(key, storage));

end:
	DBG_TRACE("Generate secret key return %ld", ret);

	if (ret == CKR_OK)
		*hkey = (CK_OBJECT_HANDLE)key;
	else
		obj_free(key, NULL);

	return ret;
}

/**
 * object_match() - Find objects in list matching atttributes
 * @hsession: Session handle
 * @list_match: List of objects matching
 * @list: List of objects
 * @attrs_match: List of the object attributes to match
 * @attrs_tmp: Template of object attributes to get
 * @nb_attrs: Number of attributes
 *
 * return:
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
static CK_RV object_match(CK_SESSION_HANDLE hsession,
			  struct libobjs_match *list_match,
			  struct libobj_list *list,
			  CK_ATTRIBUTE_PTR attrs_match,
			  CK_ATTRIBUTE_PTR attrs_tmp, CK_ULONG nb_attrs)
{
	CK_RV ret = CKR_OK;
	struct libobj_obj *obj = NULL;
	struct libobj_handles *obj_match = NULL;
	CK_ULONG idx = 0;
	bool match = false;

	for (obj = LIST_FIRST(list); obj; obj = LIST_NEXT(obj)) {
		DBG_TRACE("Check if object %p match", obj);
		if (nb_attrs) {
			for (idx = 0; idx < nb_attrs; idx++) {
				attrs_tmp[idx].ulValueLen =
					attrs_match[idx].ulValueLen;
				memset(attrs_tmp[idx].pValue, 0,
				       attrs_tmp[idx].ulValueLen);
			}

			ret = libobj_get_attribute(hsession,
						   (CK_OBJECT_HANDLE)obj,
						   attrs_tmp, nb_attrs);
			if (ret != CKR_OK)
				continue;

			match = true;
			for (idx = 0; idx < nb_attrs; idx++) {
				if (attrs_tmp[idx].ulValueLen !=
					    attrs_match[idx].ulValueLen ||
				    memcmp(attrs_tmp[idx].pValue,
					   attrs_match[idx].pValue,
					   attrs_match[idx].ulValueLen)) {
					match = false;
					break;
				}
			}
			if (!match)
				continue;
		}

		obj_match = malloc(sizeof(*obj_match));
		if (!obj_match)
			return CKR_HOST_MEMORY;

		obj_match->handle = (CK_OBJECT_HANDLE)obj;
		LIST_INSERT_TAIL(list_match, obj_match);
	}

	return ret;
}

static void destroy_query_list(struct libobj_query *query)
{
	struct libobj_handles *obj = NULL;
	struct libobj_handles *next = NULL;

	if (query) {
		obj = LIST_FIRST(&query->objects);
		while (obj) {
			next = LIST_NEXT(obj);
			free(obj);
			obj = next;
		}

		free(query);
	}
}

CK_RV libobj_find_init(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		       CK_ULONG nb_attrs)
{
	CK_RV ret = CKR_OK;
	struct libobj_query *query = NULL;
	struct libobj_list *objects = NULL;
	struct libdevice *dev = NULL;
	CK_ULONG idx = 0;
	CK_ATTRIBUTE_PTR attrs_tmp = NULL;

	DBG_TRACE("Start Find Object Query on session %lu", hsession);

	/*
	 * Check if a query is already started, if this is the
	 * case return in error.
	 */
	ret = libsess_get_query(hsession, &query);
	if (ret != CKR_OK)
		return ret;

	if (query)
		return CKR_OPERATION_ACTIVE;

	ret = libsess_get_device(hsession, &dev);
	if (ret != CKR_OK)
		return ret;

	if (nb_attrs) {
		attrs_tmp = calloc(1, nb_attrs * sizeof(CK_ATTRIBUTE));
		if (!attrs_tmp)
			return CKR_HOST_MEMORY;

		for (idx = 0; idx < nb_attrs; idx++) {
			attrs_tmp[idx].type = attrs[idx].type;
			attrs_tmp[idx].ulValueLen = attrs[idx].ulValueLen;
			if (!attrs_tmp[idx].ulValueLen) {
				ret = CKR_ATTRIBUTE_VALUE_INVALID;
				goto end;
			}
			attrs_tmp[idx].pValue =
				calloc(1, attrs_tmp[idx].ulValueLen);
			if (!attrs_tmp[idx].pValue) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}
		}
	}

	query = malloc(sizeof(*query));
	if (!query) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	LIST_INIT(&query->objects);

	/*
	 * First go thru token's objects
	 */
	DBG_TRACE("Check if token's objects");
	ret = object_match(hsession, &query->objects, &dev->objects, attrs,
			   attrs_tmp, nb_attrs);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Next go thru session's objects
	 */
	DBG_TRACE("Check if session's objects");
	ret = libsess_get_objects(hsession, &objects);
	if (ret == CKR_OK)
		ret = object_match(hsession, &query->objects, objects, attrs,
				   attrs_tmp, nb_attrs);

	if (ret == CKR_OK) {
		ret = libsess_set_query(hsession, query);
		if (ret == CKR_SESSION_HANDLE_INVALID)
			ret = CKR_SESSION_CLOSED;
	}

end:
	DBG_TRACE("Start Find Object Query on session %lu return %ld", hsession,
		  ret);

	if (attrs_tmp) {
		for (idx = 0; idx < nb_attrs; idx++)
			if (attrs_tmp[idx].pValue)
				free(attrs_tmp[idx].pValue);

		free(attrs_tmp);
	}

	if (ret != CKR_OK && query)
		destroy_query_list(query);

	return ret;
}

CK_RV libobj_find(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE_PTR pobjs,
		  CK_ULONG nb_objs_max, CK_ULONG_PTR pnb_objs_found)
{
	CK_RV ret = CKR_OK;
	struct libobj_query *query = NULL;
	struct libobj_handles *obj = NULL;
	struct libobj_handles *next = NULL;
	CK_ULONG rem_objs = nb_objs_max;
	CK_OBJECT_HANDLE_PTR out_objs = pobjs;

	DBG_TRACE("Find Objects max=%lu on session %lu", nb_objs_max, hsession);
	ret = libsess_get_query(hsession, &query);
	if (ret != CKR_OK)
		goto end;

	*pnb_objs_found = 0;
	for (obj = LIST_FIRST(&query->objects); obj && rem_objs; rem_objs--) {
		*out_objs = obj->handle;
		next = LIST_NEXT(obj);
		LIST_REMOVE(&query->objects, obj);
		free(obj);
		obj = next;

		if (INC_OVERFLOW(*pnb_objs_found, 1))
			return CKR_GENERAL_ERROR;

		out_objs++;
	}

end:
	DBG_TRACE("Find Objects found %lu on session %lu return %ld",
		  *pnb_objs_found, hsession, ret);

	return ret;
}

CK_RV libobj_find_final(CK_SESSION_HANDLE hsession)
{
	CK_RV ret = CKR_OK;
	struct libobj_query *query = NULL;

	DBG_TRACE("Final Find Object Query on session %lu", hsession);
	ret = libsess_get_query(hsession, &query);

	if (ret == CKR_OK && query) {
		destroy_query_list(query);
		ret = libsess_set_query(hsession, NULL);
	}

	DBG_TRACE("Final Find Object Query on session %lu return %ld", hsession,
		  ret);

	return ret;
}

CK_RV libobj_list_destroy(struct libobj_list *list)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libobj_obj *obj = NULL;
	struct libobj_obj *next = NULL;

	DBG_TRACE("Destroy all objects from list %p", list);

	if (!list)
		return ret;

	/* Lock the list until the end of the destruction */
	ret = LLIST_LOCK(list);
	if (ret != CKR_OK)
		return ret;

	obj = LIST_FIRST(list);
	while (obj) {
		next = LIST_NEXT(obj);

		ret = libmutex_lock(obj->lock);
		if (ret != CKR_OK) {
			LLIST_UNLOCK(list);
			return ret;
		}

		obj_free(obj, list);
		obj = next;
	}

	/* Close the list and destroy the list mutex */
	LLIST_CLOSE(list);

	return ret;
}
