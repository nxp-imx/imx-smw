// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <util.h>
#include <string.h>
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
 * struct obj_list - Transient object list.
 * @obj_data: Object data.
 * @next: Next object of the list.
 */
struct obj_list {
	struct obj_data *obj_data;
	struct obj_list *next;
};

/* Linked list containing transient objects */
static struct obj_list *transient_object_list;

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
	TEE_Result res = TEE_SUCCESS;

	FMSG("Executing %s", __func__);

	res = ta_find_and_open_persistent_id(id, NULL, true);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = ta_find_and_get_transient_id(id, NULL);

	return res;
}

TEE_Result ta_find_and_open_persistent_id(uint32_t id, TEE_ObjectHandle *handle,
					  bool shared)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectEnumHandle obj_enum = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	uint32_t *obj_id = NULL;
	size_t obj_id_length = 0;
	bool found = false;
	uint32_t persistent_object_flags =
		PERSISTENT_OBJECT_FLAGS |
		(shared ? 0 : TEE_DATA_FLAG_ACCESS_WRITE_META);

	FMSG("Executing %s", __func__);

	res = TEE_AllocatePersistentObjectEnumerator(&obj_enum);
	if (res == TEE_SUCCESS) {
		obj_id = TEE_Malloc(OBJECT_ID_BUFFER_MAX,
				    TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!obj_id) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		DMSG("Enumerate all Persistent objects");
		res = TEE_StartPersistentObjectEnumerator(obj_enum,
							  SMW_TEE_STORAGE);

		while (res == TEE_SUCCESS && !found) {
			TEE_MemFill(&obj_info, 0, sizeof(obj_info));
			TEE_MemFill(obj_id, 0, OBJECT_ID_BUFFER_MAX);
			obj_id_length = 0;

			res = TEE_GetNextPersistentObject(obj_enum, &obj_info,
							  obj_id,
							  &obj_id_length);
			if (res == TEE_SUCCESS && obj_id_length == sizeof(id) &&
			    id == obj_id[0])
				found = true;
		}
	}

	if (found) {
		DMSG("Persistent object ID 0x%08" PRIx32 " found", id);
		if (handle)
			res = TEE_OpenPersistentObject(SMW_TEE_STORAGE, obj_id,
						       sizeof(*obj_id),
						       persistent_object_flags,
						       handle);
	} else {
		res = TEE_ERROR_ITEM_NOT_FOUND;
	}

exit:
	TEE_FreePersistentObjectEnumerator(obj_enum);

	if (obj_id)
		TEE_Free(obj_id);

	return res;
}

TEE_Result ta_find_and_get_transient_id(uint32_t id, struct obj_data *obj_data)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	struct obj_list *head = transient_object_list;

	FMSG("Executing %s", __func__);

	while (head && res != TEE_SUCCESS) {
		if (head->obj_data->id == id) {
			res = TEE_SUCCESS;
			if (obj_data)
				*obj_data = *head->obj_data;
		}

		head = head->next;
	}

	return res;
}

TEE_Result ta_register_persistent_object(struct obj_data *obj_data)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle handle = TEE_HANDLE_NULL;

	FMSG("Executing %s", __func__);

	if (!obj_data)
		return res;

	res = TEE_CreatePersistentObject(SMW_TEE_STORAGE, &obj_data->id,
					 sizeof(obj_data->id),
					 PERSISTENT_OBJECT_FLAGS,
					 obj_data->handle, NULL, 0, &handle);

	if (obj_data->data && obj_data->data_size) {
		res = TEE_WriteObjectData(handle, obj_data->data,
					  obj_data->data_size);
		if (res != TEE_SUCCESS)
			(void)TEE_CloseAndDeletePersistentObject1(handle);
	}

	if (res == TEE_SUCCESS)
		TEE_CloseObject(handle);

	return res;
}

TEE_Result ta_find_and_delete_persistent_id(uint32_t id)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle handle = TEE_HANDLE_NULL;

	FMSG("Executing %s", __func__);

	res = ta_find_and_open_persistent_id(id, &handle, false);
	if (res == TEE_SUCCESS)
		res = TEE_CloseAndDeletePersistentObject1(handle);

	return res;
}

TEE_Result ta_register_transient_object(struct obj_data *obj_data)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct obj_data *new_obj_data = NULL;
	struct obj_list *new_obj = NULL;
	struct obj_list *head = NULL;

	FMSG("Executing %s", __func__);

	if (!obj_data)
		goto exit;

	new_obj_data = TEE_Malloc(sizeof(*new_obj_data),
				  TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!new_obj_data) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	*new_obj_data = *obj_data;
	new_obj_data->data = NULL;
	new_obj_data->data_size = 0;

	if (obj_data->data && obj_data->data_size) {
		new_obj_data->data = TEE_Malloc(obj_data->data_size,
						TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!new_obj_data->data) {
			EMSG("TEE_Malloc failed");
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		TEE_MemMove(new_obj_data->data, obj_data->data,
			    obj_data->data_size);

		new_obj_data->data_size = obj_data->data_size;
	}

	new_obj = TEE_Malloc(sizeof(*new_obj), TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!new_obj) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	new_obj->obj_data = new_obj_data;
	new_obj->next = NULL;

	if (!transient_object_list) {
		/* New object is the first of the list */
		transient_object_list = new_obj;
	} else {
		head = transient_object_list;
		while (head->next)
			head = head->next;
		/* New object is the last of the list */
		head->next = new_obj;
	}

	res = TEE_SUCCESS;
	obj_data->handle = TEE_HANDLE_NULL;

exit:
	if (res != TEE_SUCCESS) {
		if (new_obj_data) {
			if (new_obj_data->data)
				TEE_Free(new_obj_data->data);

			TEE_Free(new_obj_data);
		}
	}

	return res;
}

TEE_Result ta_find_and_delete_transient_id(uint32_t id)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	struct obj_list *head = NULL;
	struct obj_list *prev = NULL;
	struct obj_list *next = NULL;

	FMSG("Executing %s", __func__);

	if (!id)
		return TEE_ERROR_BAD_PARAMETERS;

	head = transient_object_list;
	prev = transient_object_list;

	while (head && res != TEE_SUCCESS) {
		next = head->next;
		if (head->obj_data->id == id) {
			res = TEE_SUCCESS;

			if (head == transient_object_list)
				transient_object_list = next;
			else
				prev->next = next;

			TEE_FreeTransientObject(head->obj_data->handle);

			if (head->obj_data->data)
				TEE_Free(head->obj_data->data);
			TEE_Free(head->obj_data);
			TEE_Free(head);

			break;
		}

		prev = head;
		head = next;
	};

	return res;
}

TEE_Result ta_find_unused_object_id(uint32_t *id, bool persistent)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	uint32_t i = OBJECT_ID_TRANSIENT_MIN;
	uint32_t max_id = OBJECT_ID_TRANSIENT_MAX;

	FMSG("Executing %s", __func__);

	if (*id) {
		DMSG("Check if ID=0x%08" PRIx32 " is free", *id);
		res = is_object_id_used(*id);
		if (res == TEE_SUCCESS)
			res = TEE_ERROR_BAD_PARAMETERS;
		else if (res == TEE_ERROR_ITEM_NOT_FOUND)
			res = TEE_SUCCESS;

	} else {
		if (persistent) {
			i = OBJECT_ID_PERSISTENT_MIN;
			max_id = OBJECT_ID_PERSISTENT_MAX;
		}

		for (; i < max_id; i++) {
			res = is_object_id_used(i);
			if (res == TEE_SUCCESS)
				continue;

			if (res == TEE_ERROR_ITEM_NOT_FOUND) {
				*id = i;
				DMSG("Found new ID=0x%08" PRIx32, *id);
				res = TEE_SUCCESS;
			}

			break;
		}

		if (i == max_id)
			res = TEE_ERROR_STORAGE_NO_SPACE;
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
	TEE_Result res = TEE_SUCCESS;
	struct obj_list *head = transient_object_list;
	struct obj_list *next = NULL;

	FMSG("Executing %s", __func__);

	while (head) {
		next = head->next;
		res = ta_find_and_delete_transient_id(head->obj_data->id);
		if (res != TEE_SUCCESS) {
			EMSG("Can't delete object from linked list: 0x%x", res);
			break;
		}

		head = next;
	}

	return res;
}
