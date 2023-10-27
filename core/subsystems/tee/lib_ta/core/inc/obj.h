/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef TA_OBJ_H
#define TA_OBJ_H

#include <util.h>

/**
 * struct obj_data - Object data.
 * @id: Object ID.
 * @handle: Object Handle
 * @data: Data buffer
 * @data_size: Data buffer size
 */
struct obj_data {
	uint32_t id;
	TEE_ObjectHandle handle;
	void *data;
	size_t data_size;
};

/**
 * ta_find_and_open_persistent_id() - Find if object ID is persistent and open it.
 * @id: ID to find.
 * @handle: If not NULL and ID found, return the persistent object handle.
 * @shared: true if the access to the object can be shared, else false.
 *
 * Return:
 * TEE_SUCCESS              - @id is present in the persistent storage
 * TEE_ERROR_ITEM_NOT_FOUND - @id is not present in the persistent storage
 * other error              - Unexpected error
 */
TEE_Result ta_find_and_open_persistent_id(uint32_t id, TEE_ObjectHandle *handle,
					  bool shared);

/**
 * ta_find_and_get_transient_id() - Find if object ID is transient and return
 *                                  its data.
 * @id: ID to find.
 * @obj_data: If not NULL and ID found, return the transient object data.
 *
 * Return:
 * TEE_SUCCESS              - @id is present in the transient id list
 * TEE_ERROR_ITEM_NOT_FOUND - @id is not present in the transient id list
 */
TEE_Result ta_find_and_get_transient_id(uint32_t id, struct obj_data *obj_data);

/**
 * ta_register_persistent_object() - Create and close a persistent object
 * @obj_data: Persistent object data
 *
 * Transforms a transient object into a persistent object and close it if
 * success.
 *
 * Return:
 * TEE_SUCCESS              - Object registered
 * other error              - Unexpected error
 */
TEE_Result ta_register_persistent_object(struct obj_data *obj_data);

/**
 * ta_find_and_delete_persistent_id() - Find and delete ID in persistent storage
 * @id: ID to find and delete.
 *
 * Checks if ID is persistent and if found, deletes it.
 *
 * Return:
 * TEE_SUCCESS              - @id found and deleted
 * TEE_ERROR_ITEM_NOT_FOUND - @id not found
 * other error              - Unexpected error
 */
TEE_Result ta_find_and_delete_persistent_id(uint32_t id);

/**
 * ta_register_transient_object() - Add transient object in the list
 * @obj_data: Transient object data
 *
 * Create a new object and push it in the transient object list.
 *
 * Return:
 * TEE_SUCCESS              - Object registered
 * other error              - Unexpected error
 */
TEE_Result ta_register_transient_object(struct obj_data *obj_data);

/**
 * ta_find_and_delete_transient_id() - Find and delete ID in transient storage
 * @id: ID to find and delete.
 *
 * Checks if ID is transient and if found, deletes it.
 *
 * Return:
 * TEE_SUCCESS              - @id found and deleted
 * TEE_ERROR_ITEM_NOT_FOUND - @id not found
 * other error              - Unexpected error
 */
TEE_Result ta_find_and_delete_transient_id(uint32_t id);

/**
 * ta_find_unused_object_id() - Find an unused object ID.
 * @id: [in/out] input object ID to find, return new object ID
 * @persistent: Object storage information.
 *
 * If the @id is 0, finds a free id in the list else checks if the
 * given @id is not used.
 *
 * Return:
 * TEE_SUCCESS                - Success.
 * TEE_ERROR_ITEM_NOT_FOUND   - Failed.
 * TEE_ERROR_BAD_PARAMETERS   - Id already used.
 * TEE_ERROR_STORAGE_NO_SPACE - Not more storage place
 * other error                - Unexpected error.
 */
TEE_Result ta_find_unused_object_id(uint32_t *id, bool persistent);

/**
 * ta_get_obj_handle() - Get the TEE object handle of a given object ID.
 * @obj_handle: Object handle.
 * @obj_id: Object ID.
 * @persistent: Set to true if object is persistent.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * Error code from internal functions.
 */
TEE_Result ta_get_obj_handle(TEE_ObjectHandle *obj_handle, uint32_t obj_id,
			     bool *persistent);

/**
 * ta_clear_obj_linked_list() - Clear object linked list.
 *
 * This function is called when the TA session is closed. Its goal is to
 * free all transient objects and free object linked list resources.
 *
 * Return:
 * TEE_SUCCESS	- Success.
 * Error code from ta_find_and_delete_transient_id() function.
 */
TEE_Result ta_clear_obj_linked_list(void);

#endif /* TA_OBJ_H */
