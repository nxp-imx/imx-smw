/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include "pkcs11smw.h"

/**
 * util_check_ptrs_null() - Verify all given pointers are NULL
 * @nb: Number of pointers to verify
 * @...: Dynamic parameters list
 *
 * Return: True if all pointers are NULL, otherwise false
 */
bool util_check_ptrs_null(int nb, ...);

/**
 * util_check_ptrs_set() - Verify all given pointers are not NULL
 * @nb: Number of pointers to verify
 * @...: Dynamic parameters list
 *
 * Return: True if all pointers are not NULL, otherwise false
 */
bool util_check_ptrs_set(int nb, ...);

/*
 * Useful macros
 */
#define BIT32(bit) (1 << (bit))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#endif /* __UTIL_H__ */
