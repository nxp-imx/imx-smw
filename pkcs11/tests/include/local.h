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

#ifndef BITS_TO_BYTES
#define BITS_TO_BYTES(size) (((size) + 7) / 8)
#endif /* BITS_TO_BYTES */

struct ckr_enum {
	CK_RV val;
	const char *const name;
};

extern const struct ckr_enum ckr_enum[];

struct test_slots {
	CK_SLOT_ID num;
	const char *label;
	CK_FLAGS flags_slot;
};

extern const struct test_slots exp_slots[];
const char *get_slot_label(CK_ULONG slotid);

#define ENUM_ENTRY(val)                                                        \
	{                                                                      \
		val, #val                                                      \
	}

#define CK_FUNCTION_PTR(name) CK_DECLARE_FUNCTION_POINTER(CK_RV, name)

extern const CK_BYTE prime192v1[];
extern const CK_BYTE prime256v1[];

int util_to_asn1_string(CK_ATTRIBUTE_PTR attr, const char *str);
int util_to_asn1_oid(CK_ATTRIBUTE_PTR attr, const CK_BYTE *oid);

void tests_pkcs11_get_info_ifs(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_get_ifs(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_slot_token(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_session(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_object(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_find(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_parallel(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);

#endif /* __LOCAL_H__ */
