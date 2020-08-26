/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * smw_utils_get_string_index() - Get the ID associated to a name.
 * @name: Name as a string.
 * @array: Array associating an ID (index) to a name (value).
 * @size: Size of @array.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID associated to a name as described in @array.
 *
 * Return:
 * error code.
 */
int smw_utils_get_string_index(const char *name, const char *const array[],
			       unsigned int size, unsigned int *id);
