// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"
#include "database.h"

void print_key_params(struct op_key *key)
{
	unsigned int i = 0;

	SMW_DBG_PRINTF(DEBUG,
		       "    key_type_bitmap: %.8lX\n"
		       "    key_size_range:\n",
		       key->type_bitmap);

	for (; i < ARRAY_SIZE(key->size_range); i++)
		SMW_DBG_PRINTF(DEBUG, "        (%u, %u)\n",
			       key->size_range[i].min, key->size_range[i].max);
}

void print_database(void)
{
	struct database *database = get_database();
	unsigned int i = 0;
	struct subsystem *subsystem = NULL;
	struct operation *operation = NULL;

	if (!database)
		return;

	SMW_DBG_PRINTF(INFO, "PSA default subsystem: %d, alternative: %s\n",
		       database->psa.subsystem_id,
		       database->psa.alt ? "ENABLED" : "DISABLED");

	SMW_DBG_PRINTF(INFO, "Secure subsystems:\n");
	for (; i < SUBSYSTEM_ID_NB; i++) {
		subsystem = &database->subsystem[i];

		SMW_DBG_PRINTF(INFO,
			       "\n"
			       "    id                : %d\n"
			       "    configured        : %s\n"
			       "    state             : %d\n"
			       "    load/unload method: %d\n",
			       i, subsystem->configured ? "true" : "false",
			       subsystem->state, subsystem->load_method_id);
	}

	SMW_DBG_PRINTF(INFO, "Security operations:\n");
	for (i = 0; i < OPERATION_ID_NB; i++) {
		SMW_DBG_PRINTF(INFO, "   operation: %s\n",
			       smw_config_get_operation_name(i));

		operation = &database->operation[i];
		smw_utils_list_print(&operation->subsystems_list);
	}
}
