/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __DATABASE_H__
#define __DATABASE_H__

#include "list.h"

#define LOAD_METHOD_ID_DEFAULT LOAD_METHOD_ID_AT_FIRST_CALL_LOAD

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

#endif /* __DATABASE_H__ */
