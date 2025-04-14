/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __KEY_GROUP_H__
#define __KEY_GROUP_H__

#include "common.h"

#define ELE_UNDEFINED_KEY_GROUP	       UINT16_MAX
#define ELE_MAX_KEY_GROUP	       100U
#define ELE_FIRST_PERSISTENT_KEY_GROUP 0U
#define ELE_FIRST_TRANSIENT_KEY_GROUP  (ELE_MAX_KEY_GROUP / 2)
#define ELE_LAST_PERSISTENT_KEY_GROUP  (ELE_FIRST_TRANSIENT_KEY_GROUP - 1)
#define ELE_LAST_TRANSIENT_KEY_GROUP   (ELE_MAX_KEY_GROUP - 1)

int ele_get_key_group(struct subsystem_context *ele_ctx, bool persistent,
		      unsigned int *out_grp);
int ele_set_key_group_state(struct subsystem_context *ele_ctx, unsigned int grp,
			    bool persistent, bool full);

#endif /* __KEY_GROUP_H__ */
