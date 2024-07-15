/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __UTIL_SUBSYSTEM_H__
#define __UTIL_SUBSYSTEM_H__

/**
 * util_subsystem_get_name() - Convert Secure Subsystem string value into integer value.
 * @subsystem_name: Pointer to Secure Subsystem name to update.
 * @string: Secure Subsystem string.
 *
 * Return:
 * None.
 */
void util_subsystem_get_name(smw_subsystem_t *subsystem_name,
			     const char *string);

#endif /* __UTIL_SUBSYSTEM_H__ */
