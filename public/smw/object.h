/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
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
 * @attributes: Object persistency attributes
 * @label: Object description
 * @group: Key group (may not be used by all subsystems)
 * @key: Key descriptor. See &struct smw_key_descriptor
 * @data: Data descriptor. See &struct smw_data_descriptor
 */
struct smw_object_descriptor {
	unsigned int id;
	smw_object_type_t type;
	smw_subsystem_t subsystem_name;
	smw_attr_attributes_t attributes;
	char *label;
	unsigned int group;
	union {
		struct smw_key_descriptor key;
		struct smw_data_descriptor data;
	};
};

#endif /* __SMW_OBJECT_H__ */
