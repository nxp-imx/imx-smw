/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __OBJECT_QUERY_H__
#define __OBJECT_QUERY_H__

#include "keymgr.h"
#include "storage.h"

enum smw_query_type {
	SMW_QUERY_TYPE_NONE,
	SMW_QUERY_TYPE_DATA,
	SMW_QUERY_TYPE_KEY,
};

struct smw_object_query {
	enum subsystem_id subsystem_id;
	enum smw_query_type type;
	union {
		struct smw_keymgr_descriptor *key;
		struct smw_storage_data_descriptor *data;
	};
};

/**
 * util_object_query_subsystem() - Query all present subsystems for an object
 * @query: Object descriptor query
 * @op_ids: Operation id subsystem must support (could be NULL)
 * @nb_ops: Number of @op_ids
 *
 * Return:
 * SMW_STATUS_OK          - Object is present in one subsystem.
 * SMW_STATUS_UNKNOWN_ID  - Object not present in any subsystems.
 */
int util_object_query_subsystem(struct smw_object_query *query,
				enum operation_id *op_ids, unsigned int nb_ops);

#endif /* __OBJECT_QUERY_H__ */
