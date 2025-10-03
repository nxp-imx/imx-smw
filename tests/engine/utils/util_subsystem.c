// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <string.h>

#include <smw/names.h>

#include "util.h"
#include "util_debug.h"
#include "util_status.h"

#define SUBSYSTEM(_name)                                                       \
	{                                                                      \
		.name = SMW_SUBSYSTEM_NAME_##_name, .string = #_name           \
	}

static struct {
	smw_subsystem_t name;
	const char *string;
} subsystem_names[] = { SUBSYSTEM(TEE),
			SUBSYSTEM(SECO),
			SUBSYSTEM(ELE),
			{ .name = SMW_SUBSYSTEM_NAME_NONE,
			  .string = "DEFAULT" } };

void util_subsystem_get_name(smw_subsystem_t *subsystem_name,
			     const char *string)
{
	unsigned int i = 0;

	if (!string) {
		*subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
		return;
	}

	for (; i < ARRAY_SIZE(subsystem_names); i++) {
		if (!strcmp(subsystem_names[i].string, string)) {
			*subsystem_name = subsystem_names[i].name;
			return;
		}
	}

	*subsystem_name = SMW_SUBSYSTEM_NAME_NB + 1;
}

const char *util_subsystem_name_to_string(smw_subsystem_t subsystem_name)
{
	const char *name = NULL;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(subsystem_names); i++) {
		if (subsystem_name != subsystem_names[i].name)
			continue;

		name = subsystem_names[i].string;
		break;
	}

	return name;
}
