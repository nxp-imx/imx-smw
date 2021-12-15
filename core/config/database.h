/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#define LOAD_METHOD_ID_DEFAULT LOAD_METHOD_ID_AT_FIRST_CALL_LOAD

enum subsystem_state { SUBSYSTEM_STATE_UNLOADED, SUBSYSTEM_STATE_LOADED };

struct subsystem {
	bool configured;
	enum subsystem_state state;
	enum load_method_id load_method_id;
};

struct operation {
	struct smw_utils_list subsystems_list;
};

struct database {
	struct psa_config psa;
	struct subsystem subsystem[SUBSYSTEM_ID_NB];
	struct operation operation[OPERATION_ID_NB];
};

extern struct database database;
