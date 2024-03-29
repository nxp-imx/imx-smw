/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023 NXP
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <pkcs11smw.h>

#include "builtin_macros.h"

#include "test_check.h"

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

struct asn1_ec_curve {
	size_t security_size;
	const char *name;
	const unsigned char *oid;
};

extern const struct asn1_ec_curve ec_curves[];

int util_to_asn1_string(CK_ATTRIBUTE_PTR attr, const char *str);
int util_to_asn1_oid(CK_ATTRIBUTE_PTR attr, const CK_BYTE *oid);

void tests_pkcs11_get_info_ifs(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_get_ifs(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_slot_token(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_session(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_object_key_ec(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_object_key_cipher(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_object_key_rsa(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_find(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_parallel(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_callback(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_digest(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_sign_verify(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_random(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_encrypt_decrypt(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc);
void tests_pkcs11_encrypt_decrypt_multipart(void *lib_hdl,
					    CK_FUNCTION_LIST_PTR pfunc);

#endif /* __LOCAL_H__ */
