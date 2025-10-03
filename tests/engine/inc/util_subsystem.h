/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
 */

#ifndef __UTIL_SUBSYSTEM_H__
#define __UTIL_SUBSYSTEM_H__

/**
 * util_subsystem_get_name() - Convert Secure Subsystem string value into
 *                             integer value.
 * @subsystem_name: Pointer to Secure Subsystem name to update.
 * @string: Secure Subsystem string.
 *
 * Return:
 * None.
 */
void util_subsystem_get_name(smw_subsystem_t *subsystem_name,
			     const char *string);

/**
 * util_subsystem_name_to_string() - Convert Secure Subsystem integer value
 *                                   into string value.
 *
 * @subsystem_name: Pointer to Secure Subsystem name to update.
 *
 * Return:
 * Subsystem string name or NULL if not found.
 */
const char *util_subsystem_name_to_string(smw_subsystem_t subsystem_name);

#endif /* __UTIL_SUBSYSTEM_H__ */
