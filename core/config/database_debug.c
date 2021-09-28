// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "list.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"
#include "database.h"

void print_database(void)
{
	unsigned int i;
	struct subsystem *subsystem;
	bool configured;
	enum subsystem_state state;
	enum load_method_id load_method_id;
	unsigned long operations_bitmap;
	struct smw_utils_list *operations_caps_list;

	SMW_DBG_PRINTF(INFO, "PSA default subsystem: %d\n",
		       database.psa_default_subsystem_id);

	SMW_DBG_PRINTF(INFO, "Secure subsystems capabilities:\n");
	for (i = 0; i < SUBSYSTEM_ID_NB; i++) {
		subsystem = &database.subsystem[i];
		configured = subsystem->configured;
		state = subsystem->state;
		load_method_id = subsystem->load_method_id;
		operations_bitmap = subsystem->operations_bitmap;
		operations_caps_list = &subsystem->operations_caps_list;

		SMW_DBG_PRINTF(INFO,
			       "\n%s%d\n"
			       "%s%s\n"
			       "%s%d\n"
			       "%s%d\n"
			       "%s%lX\n",
			       "    id                : ", i,
			       "    configured        : ",
			       configured ? "true" : "false",
			       "    state             : ", state,
			       "    load/unload method: ", load_method_id,
			       "    operations_bitmap : ", operations_bitmap);
		if (configured)
			smw_utils_list_print(operations_caps_list);
	}

	SMW_DBG_PRINTF(INFO, "Default subsystems:\n");
	for (i = 0; i < OPERATION_ID_NB; i++) {
		SMW_DBG_PRINTF(INFO, "    [%d] = %d\n", i,
			       database.operation[i]);
	}
}
