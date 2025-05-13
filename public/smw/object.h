/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
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
 * @id: Object identifier
 * @type: Defines the object type. See &typedef smw_object_type_t
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @persistency: Object persistency attributes. See &typedef smw_attr_attributes_t.
 * @label: Object description
 * @user_id: User defined ID
 * @group: Key group (may not be used by all subsystems)
 * @key: Key descriptor. See &struct smw_key_descriptor
 * @data: Data descriptor. See &struct smw_data_descriptor
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
 * @version: Version of this structure
 * @object_descriptor: Object descriptor. See &struct smw_object_descriptor.
 * @ctx: Find operation opaque context.
 *
 * The @ctx is allocated by the init step of the find operation and destroyed
 * by the final step of the find operation.
 * In case of one-shot operation finding the object by its id, the @ctx is
 * not used.
 */
struct smw_find_object_db_args {
	unsigned char version;
	struct smw_object_descriptor *object_descriptor;
	void *ctx;
};

/**
 * smw_update_object_db() - Update a database object.
 * @descriptor: Object descriptor. See &struct smw_object_descriptor.
 *
 * This function updates the Object attribute list.
 *
 * Return:
 * See &enum smw_status_code
 *  - Common return codes
 */
enum smw_status_code
smw_update_object_db(struct smw_object_descriptor *descriptor);

/**
 * smw_find_object_db() - Find an object by its id.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function return the object descriptor matching the id.
 * The find operation context is not used in this operation.
 *
 * Return:
 * See &enum smw_status_code
 *  - Common return codes
 */
enum smw_status_code smw_find_object_db(struct smw_find_object_db_args *args);

/**
 * smw_find_object_db_init() - Initialize the find context.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function allocates and initialises the find context.
 * If this API returns success, smw_find_object_db_final() must be called
 * to free the allocated context operation.
 *
 * Return:
 * See &enum smw_status_code
 *  - Common return codes
 */
enum smw_status_code
smw_find_object_db_init(struct smw_find_object_db_args *args);

/**
 * smw_find_object_db_next() - Find next matching Object.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function returns the next find Object.
 *
 * Return:
 * See &enum smw_status_code
 *  - Common return codes
 */
enum smw_status_code
smw_find_object_db_next(struct smw_find_object_db_args *args);

/**
 * smw_find_object_db_final() - Finalize the find context.
 * @args: Pointer to the structure that contains the find object arguments.
 *
 * This function destroys the given find context.
 *
 * Return:
 * See &enum smw_status_code
 *  - Common return codes
 */
enum smw_status_code
smw_find_object_db_final(struct smw_find_object_db_args *args);

#endif /* __SMW_OBJECT_H__ */
