/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2025-2026 NXP
 */
#ifndef __UTIL_LIB_H__
#define __UTIL_LIB_H__

#include <pkcs11smw.h>

char *util_lib_get_strerror(void);
void *util_lib_open(const char *libname);
void util_lib_close(void *handle);
CK_FUNCTION_LIST_PTR util_lib_get_func_list(void *handle);
CK_BBOOL util_lib_is_mech_supported(CK_VOID_PTR pfunc, CK_SLOT_ID slot,
				    CK_MECHANISM_TYPE mech);
CK_BBOOL util_lib_check_version(CK_VOID_PTR pfunc, CK_VERSION_PTR minimal);

#endif /* __UTIL_LIB_H__ */
