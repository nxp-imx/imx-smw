/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __OBJECT_H__
#define __OBJECT_H__

enum smw_object_persistence_id {
	/* Object persistence */
	SMW_OBJECT_PERSISTENCE_ID_TRANSIENT,
	SMW_OBJECT_PERSISTENCE_ID_PERSISTENT,
	SMW_OBJECT_PERSISTENCE_ID_PERMANENT,
	SMW_OBJECT_PERSISTENCE_ID_NB,
	SMW_OBJECT_PERSISTENCE_ID_INVALID
};

/**
 * smw_object_get_persistence_name() - Get the persistence name.
 * @persistence_id: Persistence ID.
 *
 * This function gets the name of a persistence.
 *
 * Return:
 * pointer to the string that is the persistence name.
 */
const char *
smw_object_get_persistence_name(enum smw_object_persistence_id persistence_id);

#endif /* __OBJECT_H__ */
