// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"
#include "util.h"

/*
 * Max public EC key size is twice 521bits
 * plus ASN.1 octets string header
 */
#define MAX_PUBLIC_KEY_LEN 136

static CK_BYTE base_key_1[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

static CK_BYTE base_key_2[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

static CK_BYTE base_key_3[] = { 0x10, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };

static CK_BYTE base_key_4[] = { 0x01, 0x22, 0xab, 0x54, 0x95, 0x36, 0x67, 0x88,
				0x09, 0x07, 0x0b, 0x0c, 0x2d, 0x7e, 0x0f, 0x1a };

static CK_BYTE base_key_5[] = {
	0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92,
	0xda, 0xa2, 0x31, 0x6d, 0xe5, 0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8,
	0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33
};

static CK_BYTE point_q_5[] = { 0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9,
			       0xb0, 0x51, 0xe1, 0xfe, 0xca, 0x57, 0x87, 0xd0,
			       0x98, 0xdf, 0xe6, 0x37, 0xfc, 0x90, 0xb9, 0xef,
			       0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11, 0x80,
			       0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52,
			       0xd6, 0x1f, 0x1c, 0x45, 0x6f, 0xa3, 0xe5, 0x9a,
			       0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf, 0x5f, 0x58,
			       0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b, 0xb3 };

static CK_BYTE salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

static CK_BYTE info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
			  0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

static CK_BYTE peer_buffer_5[] = {
	0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7,
	0x02, 0x70, 0x39, 0x8c, 0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc,
	0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63, 0x56,
	0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c,
	0x13, 0xc5, 0x8d, 0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f,
	0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab
};

#define HKDF_TEST_VECTOR(_id, _hash_algo, _salt, _salt_len, _info, _info_len,  \
			 _key_type, _mech, _derived_key_len, _token)           \
	{                                                                      \
		.base_key = base_key_##_id,                                    \
		.base_key_len = ARRAY_SIZE(base_key_##_id),                    \
		.hash_algo = CKM_##_hash_algo, .salt = _salt,                  \
		.salt_len = _salt_len, .info = _info, .info_len = _info_len,   \
		.derived_key_type = CKK_##_key_type,                           \
		.derived_key_len = _derived_key_len,                           \
		.allow_derived_key_mech = CKM_##_mech, .is_token_key = _token  \
	}

struct {
	CK_BYTE_PTR base_key;
	CK_ULONG base_key_len;
	CK_MECHANISM_TYPE hash_algo;
	CK_BYTE_PTR salt;
	CK_ULONG salt_len;
	CK_BYTE_PTR info;
	CK_ULONG info_len;
	CK_KEY_TYPE derived_key_type;
	CK_ULONG derived_key_len;
	CK_MECHANISM_TYPE allow_derived_key_mech;
	CK_BBOOL is_token_key;
} derive_tests[] = {
	HKDF_TEST_VECTOR(1, SHA256, salt, ARRAY_SIZE(salt), info,
			 ARRAY_SIZE(info), AES, AES_ECB, 32, false),
	HKDF_TEST_VECTOR(2, SHA384, NULL, 0, info, ARRAY_SIZE(info),
			 SHA384_HMAC, SHA384_HMAC, 48, false),
	HKDF_TEST_VECTOR(2, SHA384, NULL, 0, info, ARRAY_SIZE(info),
			 GENERIC_SECRET, SHA384_HMAC, 48, false),
	HKDF_TEST_VECTOR(3, SHA256, salt, ARRAY_SIZE(salt), NULL, 0, AES,
			 AES_CBC, 32, false),
	HKDF_TEST_VECTOR(4, SHA384, NULL, 0, NULL, 0, SHA384_HMAC, SHA384_HMAC,
			 48, false),
};

#define ECDH_TEST_VECTOR(_id, _key_type, _mech, _derived_key_len, _token)      \
	{                                                                      \
		.base_key = base_key_##_id,                                    \
		.base_key_len = ARRAY_SIZE(base_key_##_id),                    \
		.point_q = point_q_##_id,                                      \
		.point_q_len = ARRAY_SIZE(point_q_##_id),                      \
		.peer_public_buffer = peer_buffer_##_id,                       \
		.peer_public_buffer_len = ARRAY_SIZE(peer_buffer_##_id),       \
		.derived_key_type = CKK_##_key_type,                           \
		.derived_key_len = _derived_key_len,                           \
		.allow_derived_key_mech = CKM_##_mech, .is_token_key = _token  \
	}

struct {
	CK_BYTE_PTR base_key;
	CK_ULONG base_key_len;
	CK_BYTE_PTR point_q;
	CK_ULONG point_q_len;
	CK_BYTE_PTR peer_public_buffer;
	CK_ULONG peer_public_buffer_len;
	CK_KEY_TYPE derived_key_type;
	CK_ULONG derived_key_len;
	CK_MECHANISM_TYPE allow_derived_key_mech;
	CK_BBOOL is_token_key;
} ecdh_derive_tests[] = {
	ECDH_TEST_VECTOR(5, AES, AES_ECB, 24, false),
	ECDH_TEST_VECTOR(5, GENERIC_SECRET, SHA_1_HMAC, 24, false),
};

static int object_derive_key_hkdf_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_KEY_TYPE base_key_type = CKK_HKDF;
	CK_BYTE base_key_buf[16] = { 0 };
	CK_MECHANISM_TYPE base_key_allowed_mech = CKM_HKDF_DERIVE;

	CK_ATTRIBUTE base_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &base_key_type, sizeof(base_key_type) },
		{ CKA_DERIVE, &ck_true, sizeof(ck_true) },
		{ CKA_VALUE, &base_key_buf, ARRAY_SIZE(base_key_buf) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) }
	};

	CK_MECHANISM derive_mech = { 0 };
	CK_HKDF_PARAMS hkdf_params = { 0 };
	CK_MECHANISM_TYPE key_allowed_mech = { CKM_AES_ECB };
	CK_ULONG key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_AES;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_DECRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create a Base key\n");
	ret = pfunc->C_CreateObject(sess, base_key_template,
				    ARRAY_SIZE(base_key_template), &base_key);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_DeriveKey(0, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Check NULL mechanism\n");
	ret = pfunc->C_DeriveKey(sess, NULL, base_key, derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("Base Key handle NULL\n");
	ret = pfunc->C_DeriveKey(sess, &derive_mech, CK_INVALID_HANDLE,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	derive_mech.mechanism = CKM_ECDSA;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Null HKDF mechanism parameter\n");
	derive_mech.mechanism = CKM_HKDF_DERIVE;
	derive_mech.pParameter = NULL;
	derive_mech.ulParameterLen = 0;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid HKDF mechanism parameter length\n");
	derive_mech.mechanism = CKM_HKDF_DERIVE;
	derive_mech.pParameter = &hkdf_params;
	derive_mech.ulParameterLen = 1;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Unsupported salt type\n");
	hkdf_params.bExtract = CK_TRUE;
	hkdf_params.bExpand = CK_TRUE;
	hkdf_params.prfHashMechanism = CKM_SHA256;
	hkdf_params.ulSaltType = CKF_HKDF_SALT_KEY;
	hkdf_params.pSalt = NULL;
	hkdf_params.hSaltKey = CK_INVALID_HANDLE;
	derive_mech.pParameter = &hkdf_params;
	derive_mech.ulParameterLen = sizeof(hkdf_params);
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_FUNCTION_NOT_SUPPORTED, "C_DeriveKey"))
		goto end;

	TEST_OUT("Salt buffer is set but salt buffer length is set to 0\n");
	hkdf_params.ulSaltType = CKF_HKDF_SALT_DATA;
	hkdf_params.pSalt = salt;
	hkdf_params.ulSaltLen = 0;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Info buffer is set but info buffer length is set to 0\n");
	hkdf_params.ulSaltLen = ARRAY_SIZE(salt);
	hkdf_params.pInfo = info;
	hkdf_params.ulInfoLen = 0;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Derived Key handle NULL\n");
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_hkdf_bad_attr(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL derive = CK_TRUE;

	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_KEY_TYPE base_key_type = CKK_SM4;
	CK_BYTE base_key_buffer[16] = { 0 };
	CK_MECHANISM_TYPE base_key_allowed_mech = CKM_HKDF_DERIVE;

	CK_ATTRIBUTE base_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &base_key_type, sizeof(base_key_type) },
		{ CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_DERIVE, &derive, sizeof(derive) },
		{ CKA_VALUE, &base_key_buffer, ARRAY_SIZE(base_key_buffer) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) },
		{ CKA_TOKEN, &ck_true, sizeof(CK_BBOOL) },
	};

	CK_MECHANISM derive_mech = { 0 };
	CK_HKDF_PARAMS hkdf_params = { 0 };
	CK_MECHANISM_TYPE key_allowed_mech = { CKM_AES_ECB };
	CK_ULONG key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_AES;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_DECRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create a base key of type CKK_SM4\n");
	ret = pfunc->C_CreateObject(sess, base_key_template,
				    ARRAY_SIZE(base_key_template), &base_key);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	derive_mech.mechanism = CKM_HKDF_DERIVE;
	hkdf_params.bExtract = CK_TRUE;
	hkdf_params.bExpand = CK_TRUE;
	hkdf_params.prfHashMechanism = CKM_SHA256;
	hkdf_params.ulSaltType = CKF_HKDF_SALT_NULL;
	hkdf_params.pSalt = NULL;
	hkdf_params.hSaltKey = CK_INVALID_HANDLE;
	derive_mech.pParameter = &hkdf_params;
	derive_mech.ulParameterLen = sizeof(hkdf_params);

	TEST_OUT("Unsupported base key type for key derivation using HKDF\n");
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_DeriveKey"))
		goto end;

	ret = pfunc->C_DestroyObject(sess, base_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	base_key = CK_INVALID_HANDLE;

	base_key_type = CKK_HKDF;
	TEST_OUT("Create a base key of type CKK_HKDF\n");
	ret = pfunc->C_CreateObject(sess, base_key_template,
				    ARRAY_SIZE(base_key_template), &base_key);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	key_len = 0;
	TEST_OUT("Derived key length is set to 0\n");
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ATTRIBUTE_VALUE_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid derived key class\n");
	secret_key_class = CKO_PUBLIC_KEY;
	key_len = 32;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCONSISTENT, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid derived key type\n");
	derived_key_type = CKK_ECDSA;
	secret_key_class = CKO_SECRET_KEY;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_KEY_TYPE_INCONSISTENT, "C_DeriveKey"))
		goto end;

	ret = pfunc->C_DestroyObject(sess, base_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_hkdf(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_BBOOL ck_true = CK_TRUE;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;

	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_KEY_TYPE base_key_type = CKK_HKDF;
	CK_ATTRIBUTE base_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &base_key_type, sizeof(base_key_type) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, NULL_PTR, 0 },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) }
	};

	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_MECHANISM derive_mech = { CKM_HKDF_DERIVE, NULL, 0 };
	CK_HKDF_PARAMS hkdf_params = { 0 };
	CK_MECHANISM_TYPE derived_key_allowed_mech[] = { CKM_AES_ECB };
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_AES;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_TOKEN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Set HKDF Full step param */
	hkdf_params.bExtract = CK_TRUE;
	hkdf_params.bExpand = CK_TRUE;

	for (; i < ARRAY_SIZE(derive_tests); i++) {
		base_key_template[3].pValue = derive_tests[i].base_key;
		base_key_template[3].ulValueLen = derive_tests[i].base_key_len;

		TEST_OUT("Create a base key\n");
		ret = pfunc->C_CreateObject(sess, base_key_template,
					    ARRAY_SIZE(base_key_template),
					    &base_key);
		if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
			goto end;

		TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
		hkdf_params.prfHashMechanism = derive_tests[i].hash_algo;
		hkdf_params.pSalt = derive_tests[i].salt;
		hkdf_params.ulSaltLen = derive_tests[i].salt_len;
		hkdf_params.pInfo = derive_tests[i].info;
		hkdf_params.ulInfoLen = derive_tests[i].info_len;

		if (hkdf_params.pSalt)
			hkdf_params.ulSaltType = CKF_HKDF_SALT_DATA;
		else
			hkdf_params.ulSaltType = CKF_HKDF_SALT_NULL;

		derive_mech.pParameter = &hkdf_params;
		derive_mech.ulParameterLen = sizeof(hkdf_params);

		derived_key_template[1].pValue =
			&derive_tests[i].derived_key_type;
		derived_key_template[2].pValue = &derive_tests[i].is_token_key;
		derived_key_template[3].pValue =
			&derive_tests[i].derived_key_len;
		derived_key_template[4].pValue =
			&derive_tests[i].allow_derived_key_mech;

		/* Depending on key type, set the key usage */
		if (derive_tests[i].derived_key_type == CKK_AES ||
		    derive_tests[i].derived_key_type == CKK_DES ||
		    derive_tests[i].derived_key_type == CKK_DES3)
			derived_key_template[5].type = CKA_ENCRYPT;
		else
			derived_key_template[5].type = CKA_SIGN;

		TEST_OUT("Derive a key from base key using HKDF\n");
		ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
					 derived_key_template,
					 ARRAY_SIZE(derived_key_template),
					 &derived_key);
		if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
			goto end;

		TEST_OUT("Delete the derived key\n");
		ret = pfunc->C_DestroyObject(sess, derived_key);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		derived_key = CK_INVALID_HANDLE;

		TEST_OUT("Delete the base key\n");
		ret = pfunc->C_DestroyObject(sess, base_key);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		base_key = CK_INVALID_HANDLE;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_perform_op(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE aes_derived_key = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE base_key_allowed_mech = CKM_HKDF_DERIVE;
	CK_KEY_TYPE key_type = CKK_HKDF;

	CK_ATTRIBUTE base_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, NULL_PTR, 0 },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) }
	};

	CK_MECHANISM derive_mech = { CKM_HKDF_DERIVE, NULL, 0 };
	CK_HKDF_PARAMS hkdf_params = { 0 };
	CK_MECHANISM_TYPE derived_key_allowed_mech = CKM_AES_ECB;
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_AES;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) }
	};

	CK_BYTE data[] = { 0x01, 0x02,	0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			   0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			   0x01, 0x02,	0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			   0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			   0x01, 0x02,	0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			   0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			   0x01, 0x02,	0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			   0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_BYTE encrypted_data[64] = { 0 };
	CK_ULONG encrypted_data_len = data_len;
	CK_BYTE recovered_data[64] = { 0 };
	CK_ULONG recovered_data_len = data_len;

	CK_MECHANISM enc_dec_mech = { CKM_AES_ECB, NULL_PTR, 0 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Set HKDF Full step param */
	hkdf_params.bExtract = CK_TRUE;
	hkdf_params.bExpand = CK_TRUE;

	base_key_template[3].pValue = base_key_1;
	base_key_template[3].ulValueLen = ARRAY_SIZE(base_key_1);

	TEST_OUT("Create a base key\n");
	ret = pfunc->C_CreateObject(sess, base_key_template,
				    ARRAY_SIZE(base_key_template), &base_key);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	hkdf_params.prfHashMechanism = CKM_SHA256;
	hkdf_params.pSalt = salt;
	hkdf_params.ulSaltLen = ARRAY_SIZE(salt);
	hkdf_params.pInfo = info;
	hkdf_params.ulInfoLen = ARRAY_SIZE(info);
	hkdf_params.ulSaltType = CKF_HKDF_SALT_DATA;
	derive_mech.pParameter = &hkdf_params;
	derive_mech.ulParameterLen = sizeof(hkdf_params);

	TEST_OUT("Derive a key from base key using HKDF Full step\n");
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &aes_derived_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Perform cipher operation using the derived key\n");

	TEST_OUT("Initialize encrypt message operation\n");
	ret = pfunc->C_EncryptInit(sess, &enc_dec_mech, aes_derived_key);
	if (ret != CKR_OK)
		return ret;

	TEST_OUT("Encrypt message\n");
	ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
			       &encrypted_data_len);
	if (ret != CKR_OK)
		return ret;

	TEST_OUT("Initialize decrypt message operation\n");
	ret = pfunc->C_DecryptInit(sess, &enc_dec_mech, aes_derived_key);
	if (ret != CKR_OK)
		return ret;

	TEST_OUT("Decrypt encrypted message data\n");
	ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
			       recovered_data, &recovered_data_len);
	if (ret != CKR_OK)
		return ret;

	if (!util_compare_buffers(data, data_len, recovered_data,
				  recovered_data_len)) {
		TEST_OUT("Decrypted data and plaintext are not same\n");
		goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_hkdf_step(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE prk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_KEY_TYPE base_key_type = CKK_HKDF;
	CK_ATTRIBUTE base_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &base_key_type, sizeof(base_key_type) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, &base_key_1, ARRAY_SIZE(base_key_1) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) }
	};

	CK_KEY_TYPE prk_key_type = CKK_HKDF;
	CK_ULONG prk_key_len = 48;
	CK_MECHANISM_TYPE prk_allowed_mech = { CKM_HKDF_DERIVE };
	CK_ATTRIBUTE prk_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &prk_key_type, sizeof(prk_key_type) },
		{ CKA_VALUE_LEN, &prk_key_len, sizeof(prk_key_len) },
		{ CKA_DERIVE, &ck_true, sizeof(ck_true) },
		{ CKA_ALLOWED_MECHANISMS, &prk_allowed_mech,
		  sizeof(prk_allowed_mech) }
	};

	CK_KEY_TYPE derived_key_type = CKK_SHA384_HMAC;
	CK_ULONG derived_key_len = 48;
	CK_MECHANISM derive_mech = { 0 };
	CK_HKDF_PARAMS hkdf_params = { 0 };
	CK_MECHANISM_TYPE derived_key_allowed_mech[] = { CKM_SHA384_HMAC };
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create a base key\n");
	ret = pfunc->C_CreateObject(sess, base_key_template,
				    ARRAY_SIZE(base_key_template), &base_key);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	/* Set CKM_HKDF_DERIVE (Extract step) mechanism parameters */
	derive_mech.mechanism = CKM_HKDF_DERIVE;
	hkdf_params.bExtract = CK_TRUE;
	hkdf_params.bExpand = CK_FALSE;
	hkdf_params.prfHashMechanism = CKM_SHA384;

	hkdf_params.pSalt = salt;
	hkdf_params.ulSaltLen = ARRAY_SIZE(salt);
	if (hkdf_params.pSalt)
		hkdf_params.ulSaltType = CKF_HKDF_SALT_DATA;
	else
		hkdf_params.ulSaltType = CKF_HKDF_SALT_NULL;

	derive_mech.pParameter = &hkdf_params;
	derive_mech.ulParameterLen = sizeof(hkdf_params);

	TEST_OUT("HKDF Extract - Derive a PRK from the base key\n");
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key, prk_template,
				 ARRAY_SIZE(prk_template), &prk);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	/* Set CKM_HKDF_DERIVE (Expand step) mechanism parameters */
	hkdf_params.bExtract = CK_FALSE;
	hkdf_params.bExpand = CK_TRUE;
	hkdf_params.prfHashMechanism = CKM_SHA384;
	hkdf_params.pInfo = info;
	hkdf_params.ulInfoLen = ARRAY_SIZE(info);
	hkdf_params.ulSaltLen = 0;
	hkdf_params.ulSaltType = CKF_HKDF_SALT_NULL;

	TEST_OUT("HKDF Expand - Derive a key from PRK\n");
	ret = pfunc->C_DeriveKey(sess, &derive_mech, prk, derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);

	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_ecdh_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS derive_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_KEY_TYPE base_key_type = CKK_EC;
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_ECDH1_DERIVE };
	CK_BYTE pubkey[MAX_PUBLIC_KEY_LEN] = { 0 };
	CK_ATTRIBUTE base_key_template[] = {
		{ CKA_CLASS, &private_key_class, sizeof(private_key_class) },
		{ CKA_KEY_TYPE, &base_key_type, sizeof(base_key_type) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, &base_key_5, ARRAY_SIZE(base_key_5) },
		{ CKA_EC_POINT, &pubkey, 0 },
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) }
	};

	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM derive_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				     sizeof(ecdh_params) };
	CK_MECHANISM_TYPE derived_key_allowed_mech[] = { CKM_AES_ECB };
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_AES;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_TOKEN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (CHECK_EXPECTED(util_to_asn1_string(&base_key_template[5],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04;		       /* octet string tag */
	pubkey[1] = ARRAY_SIZE(point_q_5) + 1; /* EC point size */
	pubkey[2] = 0x04;		       /* Uncompress point */

	memcpy(&pubkey[3], point_q_5, ARRAY_SIZE(point_q_5));
	base_key_template[4].ulValueLen = ARRAY_SIZE(point_q_5) + 3;

	TEST_OUT("Create a Base key\n");
	ret = pfunc->C_CreateObject(sess, base_key_template,
				    ARRAY_SIZE(base_key_template), &base_key);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	derive_mech.mechanism = CKM_ECDSA;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Null ECDH mechanism parameter\n");
	derive_mech.mechanism = CKM_ECDH1_DERIVE;
	derive_mech.pParameter = NULL;
	derive_mech.ulParameterLen = 0;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid ECDH mechanism parameter length\n");
	derive_mech.mechanism = CKM_ECDH1_DERIVE;
	derive_mech.pParameter = &ecdh_params;
	derive_mech.ulParameterLen = 1;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("peer public buffer is set but length is set to 0\n");
	derive_mech.ulParameterLen = sizeof(ecdh_params);
	ecdh_params.kdf = CKD_NULL;
	ecdh_params.pPublicData = peer_buffer_5;
	ecdh_params.ulPublicDataLen = 0;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("Shared buffer is NULL but length is not set to 0\n");
	ecdh_params.kdf = CKD_NULL;
	ecdh_params.pPublicData = peer_buffer_5;
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer_5);
	ecdh_params.pSharedData = NULL;
	ecdh_params.ulSharedDataLen = 1;
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_FUNCTION_NOT_SUPPORTED, "C_DeriveKey"))
		goto end;

	TEST_OUT("Unsupported Shared buffer is set\n");
	ecdh_params.kdf = CKD_SHA256_KDF;
	ecdh_params.pPublicData = peer_buffer_5;
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer_5);
	ecdh_params.pSharedData = info;
	ecdh_params.ulSharedDataLen = sizeof(info);
	ret = pfunc->C_DeriveKey(sess, &derive_mech, base_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_FUNCTION_NOT_SUPPORTED, "C_DeriveKey"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (base_key_template[5].pValue)
		free(base_key_template[5].pValue);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_ecdh(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS derive_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_KEY_TYPE base_key_type = CKK_EC;
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_ECDH1_DERIVE };
	CK_BYTE pubkey[MAX_PUBLIC_KEY_LEN] = { 0 };
	CK_ATTRIBUTE base_key_template[] = {
		{ CKA_CLASS, &private_key_class, sizeof(private_key_class) },
		{ CKA_KEY_TYPE, &base_key_type, sizeof(base_key_type) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, NULL_PTR, 0 },
		{ CKA_EC_POINT, &pubkey, 0 },
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) }
	};

	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM mechanism = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_MECHANISM_TYPE derived_key_allowed_mech[] = { CKM_AES_ECB };
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_AES;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_TOKEN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (CHECK_EXPECTED(util_to_asn1_string(&base_key_template[5],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	for (; i < ARRAY_SIZE(ecdh_derive_tests); i++) {
		base_key_template[3].pValue = ecdh_derive_tests[i].base_key;
		base_key_template[3].ulValueLen =
			ecdh_derive_tests[i].base_key_len;

		/*
		 * Set EC Public point
		 */
		pubkey[0] = 0x04; /* octet string tag */
		pubkey[1] = ecdh_derive_tests[i].point_q_len +
			    1;	  /* EC point size */
		pubkey[2] = 0x04; /* Uncompress point */

		memcpy(&pubkey[3], ecdh_derive_tests[i].point_q,
		       ecdh_derive_tests[i].point_q_len);
		base_key_template[4].ulValueLen =
			ecdh_derive_tests[i].point_q_len + 3;

		TEST_OUT("Create a base key\n");
		ret = pfunc->C_CreateObject(sess, base_key_template,
					    ARRAY_SIZE(base_key_template),
					    &base_key);
		if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
			goto end;

		TEST_OUT("Set CKM_ECDH1_DERIVE mechanism parameters\n");
		ecdh_params.kdf = CKD_NULL;
		ecdh_params.pSharedData = NULL;
		ecdh_params.ulSharedDataLen = 0;
		ecdh_params.pPublicData =
			ecdh_derive_tests[i].peer_public_buffer;
		ecdh_params.ulPublicDataLen =
			ecdh_derive_tests[i].peer_public_buffer_len;

		ret = pfunc->C_DeriveKey(sess, &mechanism, base_key,
					 derived_key_template,
					 ARRAY_SIZE(derived_key_template),
					 &derived_key);
		if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
			goto end;

		TEST_OUT("Delete the derived key\n");
		ret = pfunc->C_DestroyObject(sess, derived_key);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		derived_key = CK_INVALID_HANDLE;

		TEST_OUT("Delete the base key\n");
		ret = pfunc->C_DestroyObject(sess, base_key);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		base_key = CK_INVALID_HANDLE;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (base_key_template[5].pValue)
		free(base_key_template[5].pValue);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_derive_key(void *lib_hdl, CK_VOID_PTR pfunc)
{
	(void)lib_hdl;
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START();

	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (object_derive_key_hkdf_bad_param(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_hkdf_bad_attr(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_hkdf(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_perform_op(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_hkdf_step(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_ecdh_bad_param(pfunc) == TEST_FAIL)
		goto end;

	status = object_derive_key_ecdh(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
