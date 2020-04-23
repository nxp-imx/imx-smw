/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#define LOAD_METHOD_ID_DEFAULT LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD

enum subsystem_state { SUBSYSTEM_STATE_UNLOADED, SUBSYSTEM_STATE_LOADED };

struct subsystem {
	bool configured;
	enum subsystem_state state;
	enum load_method_id load_method_id;
	unsigned long operations_bitmap;
	struct smw_utils_list operations_caps_list;
};

struct database {
	struct subsystem subsystem[SUBSYSTEM_ID_NB];
	enum subsystem_id operation[OPERATION_ID_NB];
};

extern struct database database;
