// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "debug.h"
#include "object.h"

static const char *const object_persistence_names[] = {
	[SMW_OBJECT_PERSISTENCE_ID_TRANSIENT] = "TRANSIENT",
	[SMW_OBJECT_PERSISTENCE_ID_PERSISTENT] = "PERSISTENT",
	[SMW_OBJECT_PERSISTENCE_ID_PERMANENT] = "PERMANENT",
};

#define OBJECT_PERSISTENCE_ID_ASSERT(id)                                       \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < SMW_OBJECT_PERSISTENCE_ID_NB) &&         \
			       (_id != SMW_OBJECT_PERSISTENCE_ID_INVALID));    \
	} while (0)

const char *
smw_object_get_persistence_name(enum smw_object_persistence_id persistence_id)
{
	unsigned int index;

	OBJECT_PERSISTENCE_ID_ASSERT(persistence_id);

	index = persistence_id;

	return object_persistence_names[index];
}
