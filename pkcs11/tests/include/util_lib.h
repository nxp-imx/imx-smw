/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_LIB_H__
#define __UTIL_LIB_H__

#include <pkcs11smw.h>

char *util_lib_get_strerror(void);
void *util_lib_open(const char *libname);
void util_lib_close(void *handle);
CK_FUNCTION_LIST_PTR util_lib_get_func_list(void *handle);

#endif /* __UTIL_LIB_H__ */
