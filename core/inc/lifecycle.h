/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024, 2026 NXP
 */

#ifndef __LIFECYCLE_H___
#define __LIFECYCLE_H___

enum smw_lifecycle_id {
	SMW_LIFECYCLE_ID_CURRENT,
	SMW_LIFECYCLE_ID_OPEN,
	SMW_LIFECYCLE_ID_CLOSED,
	SMW_LIFECYCLE_ID_CLOSED_LOCKED,
	SMW_LIFECYCLE_ID_OEM_RETURN,
	SMW_LIFECYCLE_ID_NXP_RETURN,
	SMW_LIFECYCLE_ID_NB,
	SMW_LIFECYCLE_ID_INVALID
};

/**
 * smw_lifecycle_set_name() - Set the device lifecycle name
 * @id: SMW internal lifecyle identifier.
 * @name: User API lifecycle name
 *
 * Function converts a internal lifecycle id to API user name.
 *
 * Return:
 * None.
 */
void smw_lifecycle_set_name(enum smw_lifecycle_id id, smw_lifecycle_t *name);

#endif /* __LIFECYCLE_H___ */
