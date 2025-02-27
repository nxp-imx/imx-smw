// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <util.h>
#include <string.h>
#include <sys/queue.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tee_subsystem.h"
#include "obj.h"

/* Persistent object access flags */
#define PERSISTENT_OBJECT_FLAGS                                                \
	(TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |              \
	 TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE)

/* Trusted storage space used by SMW */
#define SMW_TEE_STORAGE TEE_STORAGE_PRIVATE

/*
 * Object ID ranges
 * Object ID ranges can be split between transient and persistent by changing
 * the below ranges definition.
 */
#define OBJECT_ID_TRANSIENT_MIN	 1
#define OBJECT_ID_TRANSIENT_MAX	 UINT32_MAX
#define OBJECT_ID_PERSISTENT_MIN 1
#define OBJECT_ID_PERSISTENT_MAX UINT32_MAX

#define OBJECT_ID_BUFFER_MAX (TEE_OBJECT_ID_MAX_LEN / sizeof(uint32_t) + 1)

/**
 * struct obj_entry - Transient object entry.
 * @obj_data: Object data.
 * @next: Next object of the list.
 */
struct obj_entry {
	struct obj_data *obj_data;
	SLIST_ENTRY(obj_entry) next;
};

/* Linked list containing objects */
static SLIST_HEAD(obj_list, obj_entry) object_list = { NULL };

static TEE_Result allocate_object(uint32_t id, struct obj_entry **obj)
{
	struct obj_data *new_obj_data = NULL;
	struct obj_entry *new_obj = NULL;

	if (!id || !obj)
		return TEE_ERROR_BAD_PARAMETERS;

	new_obj_data = TEE_Malloc(sizeof(*new_obj_data),
				  TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!new_obj_data) {
		EMSG("TEE_Malloc failed");
		goto exit;
	}

	new_obj_data->id = id;
	new_obj_data->handle = TEE_HANDLE_NULL;
	new_obj_data->data = NULL;
	new_obj_data->data_size = 0;

	new_obj = TEE_Malloc(sizeof(*new_obj), TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!new_obj) {
		EMSG("TEE_Malloc failed");
		goto exit;
	}

	new_obj->obj_data = new_obj_data;
	*obj = new_obj;

	return TEE_SUCCESS;

exit:
	if (new_obj_data)
		TEE_Free(new_obj_data);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result add_object(uint32_t id, struct obj_entry **new_obj)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct obj_entry *obj = NULL;
	struct obj_entry *entry = NULL;
	struct obj_entry *previous = NULL;

	if (!id)
		return res;

	res = allocate_object(id, &obj);
	if (res != TEE_SUCCESS)
		return res;

	if (new_obj)
		*new_obj = obj;

	entry = SLIST_FIRST(&object_list);
	if (entry && entry->obj_data->id < id) {
		do {
			previous = entry;
			entry = SLIST_NEXT(entry, next);
		} while (entry && entry->obj_data->id < id);

		SLIST_INSERT_AFTER(previous, obj, next);
	} else {
		SLIST_INSERT_HEAD(&object_list, obj, next);
	}

	return TEE_SUCCESS;
}

static TEE_Result get_object(uint32_t id, struct obj_data *obj_data)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	struct obj_entry *entry = NULL;

	if (!id)
		return TEE_ERROR_BAD_PARAMETERS;

	SLIST_FOREACH(entry, &object_list, next)
	{
		if (entry->obj_data->id == id) {
			if (obj_data)
				*obj_data = *entry->obj_data;

			res = TEE_SUCCESS;
			goto end;
		} else if (entry->obj_data->id > id) {
			goto end;
		}
	}

end:
	return res;
}

static TEE_Result get_free_object_slot(uint32_t *id, bool persistent)
{
	uint32_t next_id = 0;
	uint32_t max_id = 0;
	struct obj_entry *entry = NULL;

	if (!id)
		return TEE_ERROR_BAD_PARAMETERS;

	if (persistent) {
		next_id = OBJECT_ID_PERSISTENT_MIN;
		max_id = OBJECT_ID_PERSISTENT_MAX;
	} else {
		next_id = OBJECT_ID_TRANSIENT_MIN;
		max_id = OBJECT_ID_TRANSIENT_MAX;
	}

	SLIST_FOREACH(entry, &object_list, next)
	{
		if (entry->obj_data->id > next_id)
			break;

		if (ADD_OVERFLOW(next_id, 1, &next_id))
			return TEE_ERROR_STORAGE_NO_SPACE;

		if (next_id == max_id)
			return TEE_ERROR_STORAGE_NO_SPACE;
	}

	*id = next_id;

	return TEE_SUCCESS;
}

static void free_object(struct obj_data *obj_data)
{
	if (obj_data) {
		if (obj_data->handle)
			TEE_FreeTransientObject(obj_data->handle);

		if (obj_data->data)
			TEE_Free(obj_data->data);

		TEE_Free(obj_data);
	}
}

static TEE_Result remove_object(uint32_t id)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	struct obj_entry *entry = NULL;
	struct obj_data *obj_data = NULL;

	if (!id)
		return TEE_ERROR_BAD_PARAMETERS;

	SLIST_FOREACH(entry, &object_list, next)
	{
		obj_data = entry->obj_data;

		if (obj_data->id == id) {
			free_object(obj_data);

			SLIST_REMOVE(&object_list, entry, obj_entry, next);

			TEE_Free(entry);

			res = TEE_SUCCESS;
			goto end;
		} else if (entry->obj_data->id > id) {
			goto end;
		}
	}

end:
	return res;
}

static void remove_all_objects(void)
{
	struct obj_entry *entry = NULL;

	while (!SLIST_EMPTY(&object_list)) {
		entry = SLIST_FIRST(&object_list);

		free_object(entry->obj_data);

		SLIST_REMOVE_HEAD(&object_list, next);

		TEE_Free(entry);
	}
}

/**
 * is_object_id_used() - Check if an ID is already used.
 * @id: ID to check.
 *
 * Return:
 * TEE_SUCCESS              - @id is already used
 * TEE_ERROR_ITEM_NOT_FOUND - @id is not used
 * other error              - Unexpected error
 */
static TEE_Result is_object_id_used(uint32_t id)
{
	FMSG("Executing %s", __func__);

	return get_object(id, NULL);
}

TEE_Result ta_find_and_open_persistent_id(uint32_t id, TEE_ObjectHandle *handle,
					  bool shared)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle hdl = TEE_HANDLE_NULL;
	uint32_t persistent_object_flags =
		PERSISTENT_OBJECT_FLAGS |
		(shared ? 0 : TEE_DATA_FLAG_ACCESS_WRITE_META);

	FMSG("Executing %s", __func__);

	res = get_object(id, NULL);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_OpenPersistentObject(SMW_TEE_STORAGE, &id, sizeof(id),
				       persistent_object_flags, &hdl);
	if (res == TEE_SUCCESS) {
		DMSG("Persistent object ID 0x%08" PRIx32 " found", id);
		if (handle)
			*handle = hdl;
	}

	return res;
}

TEE_Result ta_find_and_get_transient_id(uint32_t id, struct obj_data *obj_data)
{
	FMSG("Executing %s", __func__);

	return get_object(id, obj_data);
}

TEE_Result ta_register_persistent_object(struct obj_data *obj_data)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle handle = TEE_HANDLE_NULL;

	FMSG("Executing %s", __func__);

	if (!obj_data)
		return res;

	if (!obj_data->data != !obj_data->data_size)
		return res;

	res = TEE_CreatePersistentObject(SMW_TEE_STORAGE, &obj_data->id,
					 sizeof(obj_data->id),
					 PERSISTENT_OBJECT_FLAGS,
					 obj_data->handle, obj_data->data,
					 obj_data->data_size, &handle);
	if (res == TEE_SUCCESS)
		res = add_object(obj_data->id, NULL);

	if (res == TEE_SUCCESS)
		TEE_CloseObject(handle);
	else
		TEE_CloseAndDeletePersistentObject(handle);

	return res;
}

TEE_Result ta_find_and_delete_persistent_id(uint32_t id)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle handle = TEE_HANDLE_NULL;

	FMSG("Executing %s", __func__);

	res = ta_find_and_open_persistent_id(id, &handle, false);
	if (res != TEE_SUCCESS)
		return res;

	res = remove_object(id);
	if (res != TEE_SUCCESS)
		return res;

	TEE_CloseAndDeletePersistentObject(handle);

	return res;
}

TEE_Result ta_register_transient_object(struct obj_data *obj_data)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct obj_entry *new_obj = NULL;

	FMSG("Executing %s", __func__);

	if (!obj_data)
		goto exit;

	res = add_object(obj_data->id, &new_obj);
	if (res != TEE_SUCCESS)
		goto exit;

	*new_obj->obj_data = *obj_data;
	new_obj->obj_data->data = NULL;
	new_obj->obj_data->data_size = 0;

	if (obj_data->data && obj_data->data_size) {
		new_obj->obj_data->data =
			TEE_Malloc(obj_data->data_size,
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!new_obj->obj_data->data) {
			EMSG("TEE_Malloc failed");
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		TEE_MemMove(new_obj->obj_data->data, obj_data->data,
			    obj_data->data_size);

		new_obj->obj_data->data_size = obj_data->data_size;
	}

	obj_data->handle = TEE_HANDLE_NULL;

exit:
	if (res != TEE_SUCCESS) {
		if (new_obj)
			remove_object(obj_data->id);
	}

	return res;
}

TEE_Result ta_find_and_delete_transient_id(uint32_t id)
{
	FMSG("Executing %s", __func__);

	if (!id)
		return TEE_ERROR_BAD_PARAMETERS;

	return remove_object(id);
}

TEE_Result ta_find_unused_object_id(uint32_t *id, bool persistent)
{
	TEE_Result res = TEE_SUCCESS;

	FMSG("Executing %s", __func__);

	if (*id) {
		DMSG("Check if ID=0x%08" PRIx32 " is free", *id);
		res = is_object_id_used(*id);
		if (res == TEE_SUCCESS)
			res = TEE_ERROR_BAD_PARAMETERS;
		else if (res == TEE_ERROR_ITEM_NOT_FOUND)
			res = TEE_SUCCESS;
	} else {
		res = get_free_object_slot(id, persistent);
		if (res == TEE_SUCCESS)
			DMSG("Found new ID=0x%08" PRIx32, *id);
	}

	EMSG("returned 0x%" PRIx32, res);
	return res;
}

TEE_Result ta_get_obj_handle(TEE_ObjectHandle *obj_handle, uint32_t obj_id,
			     bool *persistent)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct obj_data obj_data = { 0 };

	if (!obj_handle || !persistent || !obj_id)
		return res;

	*persistent = false;

	res = ta_find_and_open_persistent_id(obj_id, obj_handle, true);
	if (res == TEE_SUCCESS) {
		*persistent = true;
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = ta_find_and_get_transient_id(obj_id, &obj_data);
		*obj_handle = obj_data.handle;
	}

	return res;
}

TEE_Result ta_clear_obj_linked_list(void)
{
	FMSG("Executing %s", __func__);

	remove_all_objects();

	return TEE_SUCCESS;
}

TEE_Result ta_get_all_persisents_obj(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectEnumHandle obj_enum = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	uint32_t *obj_id = NULL;
	size_t obj_id_len = 0;

	FMSG("Executing %s", __func__);

	/*
	 * Update object list with existing secure storage content.
	 */
	res = TEE_AllocatePersistentObjectEnumerator(&obj_enum);
	if (res != TEE_SUCCESS)
		goto exit;

	DMSG("Enumerate all Persistent objects");
	res = TEE_StartPersistentObjectEnumerator(obj_enum, SMW_TEE_STORAGE);
	if (res == TEE_SUCCESS) {
		obj_id = TEE_Malloc(OBJECT_ID_BUFFER_MAX,
				    TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!obj_id) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		while (res == TEE_SUCCESS) {
			TEE_MemFill(obj_id, 0, OBJECT_ID_BUFFER_MAX);
			obj_id_len = 0;

			res = TEE_GetNextPersistentObject(obj_enum, &obj_info,
							  obj_id, &obj_id_len);
			if (res == TEE_SUCCESS &&
			    obj_id_len == sizeof(uint32_t))
				res = add_object(*obj_id, NULL);
		}
	}

	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = TEE_SUCCESS;

exit:
	if (res != TEE_SUCCESS)
		remove_all_objects();

	return res;
}
