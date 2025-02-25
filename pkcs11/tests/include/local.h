/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023-2025 NXP
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <pkcs11smw.h>

#include "builtin_macros.h"

#include "test_check.h"

/*
 * ANSI Uncompress key tag
 */
#define ANSI_UNCOMPRESS_KEY_TAG 0x04

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

/* ECDSA curves index */
#define SECP_R1_192 0
#define SECP_R1_224 1
#define SECP_R1_521 2
#define SECP_R1_256 3
#define SECP_R1_384 4

/* Edwards curves index */
#define EC_ED25519 0

struct asn1_ec_curve {
	size_t security_size;
	const char *name;
	const unsigned char *oid;
	size_t oid_len;
};

extern const struct asn1_ec_curve ec_curves[];
extern const struct asn1_ec_curve ed_curves[];

int util_to_asn1_string(CK_ATTRIBUTE_PTR attr,
			const struct asn1_ec_curve *curve);
int util_to_asn1_oid(CK_ATTRIBUTE_PTR attr, const struct asn1_ec_curve *curve);
int util_asn1_encode_octet_string(CK_BYTE_PTR in, CK_ULONG inlen, uint8_t *out,
				  size_t *outlen);
int util_asn1_get_field_octet_string(CK_BYTE_PTR in, CK_ULONG inlen,
				     CK_BYTE_PTR *out, size_t *outlen);

void tests_pkcs11_get_info_ifs(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_get_ifs(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_slot_token(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_session(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_object_key_ec(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_object_key_edwards(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_object_key_cipher(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_object_key_rsa(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_find(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_find_ext(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_parallel(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_callback(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_digest(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_sign_verify(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_sign_verify_message(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_sign_verify_multipart(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_sign_verify_multipart_message(void *lib_hdl,
						CK_VOID_PTR pfunc);
void tests_pkcs11_random(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_encrypt_decrypt(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_encrypt_decrypt_aead(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_encrypt_decrypt_message(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_encrypt_decrypt_multipart(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_encrypt_decrypt_multipart_message(void *lib_hdl,
						    CK_VOID_PTR pfunc);
void tests_pkcs11_data_storage(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_objects(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_derive_key(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_operation_state(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_object_profile(void *lib_hdl, CK_VOID_PTR pfunc);
void tests_pkcs11_object_cert(void *lib_hdl, CK_VOID_PTR pfunc);

#endif /* __LOCAL_H__ */
