// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
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
	unsigned int i;

	SMW_DBG_PRINTF(DEBUG,
		       "    key_type_bitmap: %.8lX\n"
		       "    key_size_range:\n",
		       key->type_bitmap);

	for (i = 0; i < ARRAY_SIZE(key->size_range); i++)
		SMW_DBG_PRINTF(DEBUG, "        (%u, %u)\n",
			       key->size_range[i].min, key->size_range[i].max);
}

void print_database(void)
{
	struct database *database = get_database();
	struct smw_config_psa_config *psa;
	unsigned int i;
	struct subsystem *subsystem;
	bool configured;
	enum subsystem_state state;
	enum load_method_id load_method_id;
	struct operation *operation;

	if (!database)
		return;

	psa = &database->psa;

	SMW_DBG_PRINTF(INFO, "PSA default subsystem: %d, alternative: %s\n",
		       psa->subsystem_id, psa->alt ? "ENABLED" : "DISABLED");

	SMW_DBG_PRINTF(INFO, "Secure subsystems:\n");
	for (i = 0; i < SUBSYSTEM_ID_NB; i++) {
		subsystem = &database->subsystem[i];
		configured = subsystem->configured;
		state = subsystem->state;
		load_method_id = subsystem->load_method_id;

		SMW_DBG_PRINTF(INFO,
			       "\n%s%d\n"
			       "%s%s\n"
			       "%s%d\n"
			       "%s%d\n",
			       "    id                : ", i,
			       "    configured        : ",
			       configured ? "true" : "false",
			       "    state             : ", state,
			       "    load/unload method: ", load_method_id);
	}

	SMW_DBG_PRINTF(INFO, "Security operations:\n");
	for (i = 0; i < OPERATION_ID_NB; i++) {
		SMW_DBG_PRINTF(INFO, "%s%s\n", "    operation: ",
			       smw_config_get_operation_name(i));
		operation = &database->operation[i];
		smw_utils_list_print(&operation->subsystems_list);
	}
}
