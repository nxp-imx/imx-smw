/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022, 2024, 2026 NXP
 */

#ifndef __DATABASE_H__
#define __DATABASE_H__

#include "list.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

#define LOAD_METHOD_ID_DEFAULT LOAD_METHOD_ID_AT_FIRST_CALL_LOAD

#define SUBSYSTEM_ID_ASSERT(id)                                                \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < SUBSYSTEM_ID_NB) &&                      \
			       (_id != SUBSYSTEM_ID_INVALID));                 \
	} while (0)

#define OPERATION_ID_ASSERT(id)                                                \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < OPERATION_ID_NB) &&                      \
			       (_id != OPERATION_ID_INVALID));                 \
	} while (0)

struct subsystem {
	bool configured;
	enum subsystem_state state;
	enum load_method_id load_method_id;
};

struct operation {
	struct smw_utils_list subsystems_list;
};

struct database {
	struct smw_config_psa_config psa;
	struct subsystem subsystem[SUBSYSTEM_ID_NB];
	struct operation operation[OPERATION_ID_NB];
};

/**
 * get_database() - Get the Configuration database
 *
 * Return:
 * Pointer to the Configuration database
 */
struct database *get_database(void);

/**
 * config_db_mutex_init() - Initialize the Configuration database mutex
 *
 * Return:
 * SMW_STATUS_OK			- successful
 * SMW_STATUS_INVALID_LIBRARY_CONTEXT	- library context is invalid
 * SMW_STATUS_MUTEX_LOCK_FAILURE	- mutex lock failure
 */
int config_db_mutex_lock(void);

/**
 * config_db_mutex_unlock() - Unlock the Configuration database mutex
 *
 * Return:
 * SMW_STATUS_OK			- successful
 * SMW_STATUS_INVALID_LIBRARY_CONTEXT	- library context is invalid
 * SMW_STATUS_MUTEX_UNLOCK_FAILURE	- mutex unlock failure
 */
int config_db_mutex_unlock(void);

/**
 * find_subsystem_per_operation() - Find a subsystem node for a given operation
 * @operation_id: The operation ID to search for
 * @subsystem_id: The subsystem ID to find
 * @node: Pointer to the node pointer to be set with the found node
 *
 * Return:
 * SMW_STATUS_OK			- successful
 * SMW_STATUS_OPERATION_NOT_CONFIGURED	- operation not configured
 */
int find_subsystem_per_operation(enum operation_id operation_id,
				 unsigned int subsystem_id, struct node **node);

/**
 * select_subsystem_implicit_op() - Find a subsystem for given implicit
 *                                  operation
 * @operation_id: [in] The operation ID to search for.
 * @subsystem_id: [in/out] The subsystem ID to find.
 *
 * The function verifies if the input subsystem ID (if defined) can execute
 * the implicit operation. If subsystem is not defined, parse the subsystems
 * present to find the first one supporting the operation.
 *
 * The @subsytem_id is updated with the id of the selected subsystem.
 *
  Return:
 * SMW_STATUS_OK                        - successful
 * SMW_STATUS_OPERATION_NOT_CONFIGURED  - operation not configured
 * SMW_STATUS_OPERATION_NOT_SUPPORTED   - operation not supported
 */
int select_subsystem_implicit_op(enum operation_id operation_id,
				 enum subsystem_id *subsystem_id);
#endif /* __DATABASE_H__ */
