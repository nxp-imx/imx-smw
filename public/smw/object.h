/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2026 NXP
 */

#ifndef __SMW_OBJECT_H__
#define __SMW_OBJECT_H__

#include <stdlib.h>

#include "smw_status.h"
#include "smw_keymgr.h"
#include "smw_storage.h"

#include "smw/attr.h"
#include "smw/names.h"

/**
 * struct smw_object_descriptor - Generic SMW object descriptor
 * @id: [in/out] Object identifier.
 * @type: [in/out] Defines the object type. See &typedef smw_object_type_t.
 * @subsystem_name: [in/out] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @persistency: [in/out] Object persistency attributes.
 *               See &typedef smw_attr_attributes_t.
 * @label: [in/out] User defined object string label.
 * @user_id: [in/out] User defined ID in base64 null terminated string.
 * @group: [in/out] Object storage group (may not be used by all subsystems).
 * @key: [in/out] Key descriptor. See &struct smw_key_descriptor.
 * @data: [in/out] Data descriptor. See &struct smw_data_descriptor.
 *
 * Depending on the type of object (key or data), the object persistency
 * is retrieved from either the @key.attributes or the @data.attributes.
 */
struct smw_object_descriptor {
	unsigned int id;
	smw_object_type_t type;
	smw_subsystem_t subsystem_name;
	smw_attr_attributes_t persistency;
	char *label;
	char *user_id;
	unsigned int group;
	union {
		struct smw_key_descriptor key;
		struct smw_data_descriptor data;
	};
};

/**
 * struct smw_find_object_db_args - Object find operation arguments
 * @version: [in] Version of this structure
 * @object_descriptor: [in/out] Object descriptor.
 *                     See &struct smw_object_descriptor.
 * @ctx: [in/out] Find operation opaque context.
 *
 * Field @ctx:\
 *
 *  - Is used only for multi-part operations.
 *  - Is allocated and initialized by smw_find_object_db_init().
 *  - Must be passed to each smw_find_object_db_next() call.
 *  - Is deleted when final operation smw_findd_object_db_final() is called.
 */
struct smw_find_object_db_args {
	unsigned char version;
	struct smw_object_descriptor *object_descriptor;
	void *ctx;
};

/**
 * smw_update_object_db() - Update a database object.
 * @descriptor: Object descriptor to update.
 *
 * This function updates the object attribute list.
 *
 * The @descriptor following fields should be used to identify the object to
 * be updated:\
 *
 *   - @id: [in] (**mandatory**) Object identifier to update.
 *   - @type: [in] (**optional**) Object type.
 *   - @subsystem_name: [in] (**optional**) Secure Subsystem name.
 *   - @persistency: [in] (**optional**) Object persistency attributes.
 *   - @key.attributes.attributes: [in] (**optional**) Key persistency, if
 *     the @type is a key type.
 *   - @data.attributes.attributes: [in] (**optional**) Data persistency, if
 *     the @type is a data type.
 *
 * The @descriptor following fields could be updated: \
 *
 *   - @label: [in] User defined object string label.
 *   - @user_id: [in] User defined ID in base64 null terminated string.
 *
 * The other @descriptor fields are ignored during the update operation.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @descriptor is NULL.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_update_object_db(struct smw_object_descriptor *descriptor);

/**
 * smw_find_object_db() - Find an object by its id.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function returns the object descriptor matching the following object
 * defined by the @args->object_descriptor following fields:\
 *
 *   - @id: [in] (**mandatory**) Object identifier to update.
 *   - @type: [in] (**optional**) Object type.
 *   - @persistency: [in] (**optional**) Object persistency attributes.
 *   - @key.attributes.attributes: [in] (**optional**) Key persistency, if
 *     the @type is a key type.
 *   - @data.attributes.attributes: [in] (**optional**) Data persistency, if
 *     the @type is a data type.
 *
 * On successful return, the @args->object_descriptor is filled with the
 * object information. The following fields are output fields:\
 *
 *   - @id: [out] Object identifier.
 *   - @type: [out] Object type.
 *   - @subsystem_name: [out] Secure Subsystem name owning the object.
 *   - @label: [out] User defined object string label.
 *   - @user_id: [out] User defined ID in base64 null terminated string.
 *   - @group: [out] Object storage group (if supported by the Secure Subsystem).
 *   - If the @type is a key type:\
 *
 *     - @key.typename: [out] Key type name.
 *     - @key.security_size: [out] Key security size.
 *     - @key.id: [out] Key identifier (same as the @id).
 *     - @key.attributes: [out] Key attributes; permitted algorithm, usage,
 *       storage id, attributes.
 *     - @buffer: Nothing returned.
 *
 *   - If the @type is a data type:\
 *
 *     - @data.identifier: [out] Data identifier (same as the @id).
 *     - @data.attributes: [out] Data attributes; storage id, attributes.
 *     - @data.data: Nothing returned.
 *     - @data.length: Nothing returned.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->object_descriptor is NULL.
 *      - @args->object_descirptor.data.data is not NULL,
 *        if @args->object_descriptor.type is not a key type.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_find_object_db(struct smw_find_object_db_args *args);

/**
 * smw_find_object_db_init() - Initialize the find object context.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function allocates a new find context for multi-part object search
 * in the SMW's database. Next, the smw_find_object_db_next() function must be
 * called in a loop to retrieve all matching objects.
 *
 * Any of the @args->object_descriptor fields can be used to filter the
 * objects to be found.
 *
 * The search is limited to peristency attribute defined in
 * the @args->object_descriptor by one of the following field:\
 *
 *   - @persistency: [in] Object persistency attributes.
 *   - @key.attributes.attributes: [in] Key persistency if @type is a key type.
 *   - @data.attributes.attributes: [in] Data persistency if @type is a data type.
 *
 * .. note::
 *   If the input @args->object_descriptor.id is set, the search in the
 *   database will be lim­ited to the object with that identifier. If the
 *   object identifier is not present in the database, the function quer­ies
 *   all subsystems to find the object (key and/or data as defined by the
 *   @args->object_descriptor.type field). As the object identifier is known,
 *   it's advised to use the function smw_find_object_db() instead.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->object_descriptor is NULL.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_find_object_db_init(struct smw_find_object_db_args *args);

/**
 * smw_find_object_db_next() - Find next matching object.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function returns one by one the object matching the query setup by the
 * smw_find_object_db_init() function.
 *
 * The operation context must be by initialized by the multi-part initialization
 * smw_find_object_db_init() API or updated by a previous
 * smw_find_object_db_next() call.
 *
 * On successful return, the @args->object_descriptor is filled with the
 * object information. The following fields are output fields:\
 *
 *   - @id: [out] Object identifier.
 *   - @type: [out] Object type.
 *   - @subsystem_name: [out] Secure Subsystem name owning the object.
 *   - @label: [out] User defined object string label.
 *   - @user_id: [out] User defined ID in base64 null terminated string.
 *   - @group: [out] Object storage group (if supported by the Secure Subsystem).
 *   - If the @type is a key type:\
 *
 *     - @key.typename: [out] Key type name.
 *     - @key.security_size: [out] Key security size.
 *     - @key.id: [out] Key identifier (same as the @id).
 *     - @key.attributes: [out] Key attributes; permitted algorithm, usage,
 *       storage id, attributes.
 *     - @buffer: Nothing returned.
 *
 *   - If the @type is a data type:\
 *
 *     - @data.identifier: [out] Data identifier (same as the @id).
 *     - @data.attributes: [out] Data attributes; storage id, attributes.
 *     - @data.data: Nothing returned.
 *     - @data.length: Nothing returned.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->object_descriptor is NULL.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_find_object_db_next(struct smw_find_object_db_args *args);

/**
 * smw_find_object_db_final() - Finalize the find context.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function close the find query and destroys the operation context.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_find_object_db_final(struct smw_find_object_db_args *args);

#endif /* __SMW_OBJECT_H__ */
