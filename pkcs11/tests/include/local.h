/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <pkcs11smw.h>

#include "test_check.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

struct ckr_enum {
	CK_RV val;
	const char *const name;
};

#define ENUM_ENTRY(val)                                                        \
	{                                                                      \
		val, #val                                                      \
	}

extern const struct ckr_enum ckr_enum[];

#define CK_FUNCTION_PTR(name) CK_DECLARE_FUNCTION_POINTER(CK_RV, name)

void tests_pkcs11_get_info_ifs(CK_FUNCTION_LIST_PTR pfunc, void *lib_hdl);
void tests_pkcs11_get_ifs(void *lib_hdl);

#endif /* __LOCAL_H__ */
