// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util.h"
#include "util_lib.h"
#include "util_session.h"

/* messagetosign */
static CK_BYTE msg[] = { 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
			 0x74, 0x6f, 0x73, 0x69, 0x67, 0x6e };

static CK_ULONG msg_len = 13;

static CK_BYTE key_256[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

static CK_BYTE key_384[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

static CK_BYTE data[] = { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };

static CK_BYTE hmac_256[] = { 0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6,
			      0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd, 0xc5,
			      0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c,
			      0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6, 0x8c, 0xf7 };

static CK_BYTE hmac_384[] = { 0xb6, 0xa8, 0xd5, 0x63, 0x6f, 0x5c, 0x6a, 0x72,
			      0x24, 0xf9, 0x97, 0x7d, 0xcf, 0x7e, 0xe6, 0xc7,
			      0xfb, 0x6d, 0x0c, 0x48, 0xcb, 0xde, 0xe9, 0x73,
			      0x7a, 0x95, 0x97, 0x96, 0x48, 0x9b, 0xdd, 0xbc,
			      0x4c, 0x5d, 0xf6, 0x1d, 0x5b, 0x32, 0x97, 0xb4,
			      0xfb, 0x68, 0xda, 0xb9, 0xf1, 0xb5, 0x82, 0xc2 };

static int sign_init_bad_params(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_mech = { 0 };
	CK_MAC_GENERAL_PARAMS mac_params = { 0 };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_OBJECT_HANDLE aes_hsecretkey_not_permitted = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_CMAC };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ULONG key_length = 32;
	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE aes_secretkey_attrs_not_perm[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
				   aes_secretkey_attrs_not_perm,
				   ARRAY_SIZE(aes_secretkey_attrs_not_perm),
				   &aes_hsecretkey_not_permitted);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_MessageSignInit(0, &sign_mech, 0);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Check key handle NULL\n");
	ret = pfunc->C_MessageSignInit(sess, &sign_mech, 0);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	sign_mech.mechanism = CKM_AES_KEY_GEN;
	ret = pfunc->C_MessageSignInit(sess, &sign_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_MessageSignInit"))
		goto end;

	sign_mech.mechanism = CKM_AES_CMAC_GENERAL;
	if (util_lib_is_mech_supported(pfunc, 0, sign_mech.mechanism) &&
	    !is_seco_subsystem()) {
		TEST_OUT("Check CKA_SIGN key flag\n");
		ret = pfunc->C_MessageSignInit(sess, &sign_mech,
					       aes_hsecretkey_not_permitted);
		if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED,
				"C_MessageSignInit"))
			goto end;
	}

	if (util_lib_is_mech_supported(pfunc, 0, sign_mech.mechanism)) {
		TEST_OUT("Check bad MAC mechanism parameters\n");
		sign_mech.pParameter = &mac_params;
		sign_mech.ulParameterLen = sizeof(mac_params);
		ret = pfunc->C_MessageSignInit(sess, &sign_mech,
					       aes_hsecretkey);
		if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID,
				"C_MessageSignInit"))
			goto end;
	}

	sign_mech.mechanism = CKM_AES_CMAC;
	if (util_lib_is_mech_supported(pfunc, 0, sign_mech.mechanism)) {
		TEST_OUT("Check ignored MAC mechanism parameters\n");
		ret = pfunc->C_MessageSignInit(sess, &sign_mech,
					       aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
			goto end;
	}

	status = TEST_PASS;

end:
	(void)pfunc->C_MessageSignInit(sess, NULL_PTR, aes_hsecretkey);

	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int verify_init_bad_params(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM verify_mech = { 0 };
	CK_MAC_GENERAL_PARAMS mac_params = { 0 };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_OBJECT_HANDLE aes_hsecretkey_not_permitted = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_CMAC };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ULONG key_length = 32;
	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE aes_secretkey_attrs_not_perm[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
				   aes_secretkey_attrs_not_perm,
				   ARRAY_SIZE(aes_secretkey_attrs_not_perm),
				   &aes_hsecretkey_not_permitted);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_MessageVerifyInit(0, &verify_mech, 0);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Check key handle NULL\n");
	ret = pfunc->C_MessageVerifyInit(sess, &verify_mech, 0);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_MessageVerifyInit"))
		goto end;

	verify_mech.mechanism = CKM_AES_KEY_GEN;
	if (util_lib_is_mech_supported(pfunc, 0, verify_mech.mechanism)) {
		TEST_OUT("Check invalid mechanism\n");
		ret = pfunc->C_MessageVerifyInit(sess, &verify_mech,
						 aes_hsecretkey);
		if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_MessageVerifyInit"))
			goto end;
	}

	verify_mech.mechanism = CKM_AES_CMAC_GENERAL;
	if (util_lib_is_mech_supported(pfunc, 0, verify_mech.mechanism) &&
	    !is_seco_subsystem()) {
		TEST_OUT("Check CKA_VERIFY key flag\n");
		ret = pfunc->C_MessageVerifyInit(sess, &verify_mech,
						 aes_hsecretkey_not_permitted);
		if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED,
				"C_MessageVerifyInit"))
			goto end;
	}

	if (util_lib_is_mech_supported(pfunc, 0, verify_mech.mechanism)) {
		TEST_OUT("Check bad MAC mechanism parameters\n");
		verify_mech.pParameter = &mac_params;
		verify_mech.ulParameterLen = sizeof(mac_params);
		ret = pfunc->C_MessageVerifyInit(sess, &verify_mech,
						 aes_hsecretkey);
		if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID,
				"C_MessageVerifyInit"))
			goto end;
	}

	verify_mech.mechanism = CKM_AES_CMAC;
	if (util_lib_is_mech_supported(pfunc, 0, verify_mech.mechanism)) {
		TEST_OUT("Check ignored MAC mechanism parameters\n");
		ret = pfunc->C_MessageVerifyInit(sess, &verify_mech,
						 aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
			goto end;
	}

	status = TEST_PASS;

end:
	(void)pfunc->C_MessageVerifyInit(sess, NULL_PTR, aes_hsecretkey);

	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_bad_params(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG data_len = 0;
	CK_ULONG sign_len = 0;
	CK_BYTE data[5] = { 0 };
	CK_BYTE signature[32] = { 0 };
	CK_MAC_GENERAL_PARAMS mac_params = 32;

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	sign_len = sizeof(signature);
	data_len = sizeof(data);

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_SignMessage(0, NULL_PTR, 0, data, data_len, signature,
				   &sign_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_SignMessage"))
		goto end;

	TEST_OUT("Check signature length pointer NULL\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, data, data_len, signature,
				   NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_SignMessage"))
		goto end;

	TEST_OUT("Check data pointer NULL\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, NULL_PTR, data_len,
				   signature, &sign_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_SignMessage"))
		goto end;

	TEST_OUT("Check data length 0\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, data, 0, signature,
				   &sign_len);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_SignMessage"))
		goto end;

	TEST_OUT("Check params pointer NULL\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, sizeof(mac_params), data,
				   data_len, signature, &sign_len);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_SignMessage"))
		goto end;

	TEST_OUT("Check params length 0\n");
	ret = pfunc->C_SignMessage(sess, &mac_params, 0, data, data_len,
				   signature, &sign_len);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_SignMessage"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int verify_bad_params(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG data_len = 0;
	CK_ULONG sign_len = 0;
	CK_BYTE data[5] = { 0 };
	CK_BYTE signature[32] = { 0 };
	CK_MAC_GENERAL_PARAMS mac_params = 32;

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	sign_len = sizeof(signature);
	data_len = sizeof(data);

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_VerifyMessage(0, NULL_PTR, 0, data, data_len, signature,
				     sign_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_VerifyMessage"))
		goto end;

	TEST_OUT("Check data pointer NULL\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, NULL_PTR, data_len,
				     signature, sign_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_VerifyMessage"))
		goto end;

	TEST_OUT("Check data length 0\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, data, 0, signature,
				     sign_len);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_VerifyMessage"))
		goto end;

	TEST_OUT("Check signature pointer NULL\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, data, data_len,
				     NULL_PTR, sign_len);
	if (CHECK_CK_RV(CKR_SIGNATURE_INVALID, "C_VerifyMessage"))
		goto end;

	TEST_OUT("Check signature length 0\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, data, data_len,
				     signature, 0);
	if (CHECK_CK_RV(CKR_SIGNATURE_LEN_RANGE, "C_VerifyMessage"))
		goto end;

	TEST_OUT("Check signature pointer NULL\n");
	ret = pfunc->C_VerifyMessage(sess, &mac_params, sizeof(mac_params),
				     data, data_len, NULL_PTR, sign_len);
	if (CHECK_CK_RV(CKR_SIGNATURE_INVALID, "C_VerifyMessage"))
		goto end;

	TEST_OUT("Check params pointer NULL\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, sizeof(mac_params), data,
				     data_len, signature, sign_len);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_VerifyMessage"))
		goto end;

	TEST_OUT("Check params length 0\n");
	ret = pfunc->C_VerifyMessage(sess, &mac_params, 0, data, data_len,
				     signature, sign_len);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_VerifyMessage"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_no_init(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG sign_len = 0;
	CK_ULONG data_len = 0;
	CK_BYTE data[5] = { 0 };
	CK_BYTE signature[32] = { 0 };

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	TEST_OUT("Message sign init with NULL mechanism");
	ret = pfunc->C_MessageSignInit(sess, NULL_PTR, 1);
	if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Message verify init with NULL mechanism");
	ret = pfunc->C_MessageVerifyInit(sess, NULL_PTR, 1);
	if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
		goto end;

	sign_len = sizeof(signature);
	data_len = sizeof(data);

	TEST_OUT("Message sign without init\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, data, data_len, signature,
				   &sign_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_SignMessage"))
		goto end;

	TEST_OUT("Message verify without init\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, data, data_len,
				     signature, sign_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyMessage"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_multiple_init(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_AES_CMAC };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_CMAC };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ULONG key_length = 32;
	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize message sign operation\n");
	ret = pfunc->C_MessageSignInit(sess, &sign_verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Check multiple message sign init with same mechanism\n");
	ret = pfunc->C_MessageSignInit(sess, &sign_verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Check multiple message sign init with different mechanism\n");
	sign_verify_mech.mechanism = CKM_DES3_CMAC;
	ret = pfunc->C_MessageSignInit(sess, &sign_verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Initialize message verify operation\n");
	ret = pfunc->C_MessageVerifyInit(sess, &sign_verify_mech,
					 aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Check multiple message verify init with same mechanism\n");
	ret = pfunc->C_MessageVerifyInit(sess, &sign_verify_mech,
					 aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Check multiple message verify init with different mech\n");
	sign_verify_mech.mechanism = CKM_AES_CMAC;
	ret = pfunc->C_MessageVerifyInit(sess, &sign_verify_mech,
					 aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Check multiple message sign init with NULL mechanism\n");
	ret = pfunc->C_MessageSignInit(sess, NULL_PTR, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Check multiple message verify init with NULL mechanism\n");
	ret = pfunc->C_MessageVerifyInit(sess, NULL_PTR, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_cmac(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_AES_CMAC };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_CMAC };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp = 0;

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ULONG key_length = 32;
	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize message sign operation\n");
	ret = pfunc->C_MessageSignInit(sess, &sign_verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
		goto end;

	/* Set a wrong signature length */
	signature_len = 15;
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Message sign with signature buffer too small\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, msg, msg_len, signature,
				   &signature_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_SignMessage"))
		goto end;

	/* Realloc signature buffer with new signature length */
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Message sign\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, msg, msg_len, signature,
				   &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignMessage"))
		goto end;

	TEST_OUT("Initialize message verify operation\n");
	ret = pfunc->C_MessageVerifyInit(sess, &sign_verify_mech,
					 aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Message verify signature\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, msg, msg_len, signature,
				     signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyMessage"))
		goto end;

	tmp = signature_len;
	signature_len *= 2;
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Initialize message sign operation\n");
	ret = pfunc->C_MessageSignInit(sess, &sign_verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Message sign with signature buffer bigger that needed\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, msg, msg_len, signature,
				   &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignMessage"))
		goto end;

	TEST_OUT("Check updated signature buffer length\n");
	if (CHECK_EXPECTED(signature_len == tmp,
			   "Signature length not updated"))
		goto end;

	TEST_OUT("Initialize message verify operation\n");
	ret = pfunc->C_MessageVerifyInit(sess, &sign_verify_mech,
					 aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Message verify signature\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, msg, msg_len, signature,
				     signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyMessage"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_hmac(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA256_HMAC };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hmac_hsecretkey = 0;
	CK_MECHANISM hmac_key_mech = { .mechanism =
					       CKM_GENERIC_SECRET_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_KEY_TYPE secret_key_type = CKK_SHA256_HMAC;
	CK_ULONG key_length = 32;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_HMAC };

	CK_ATTRIBUTE hmac_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate HMAC secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &hmac_key_mech, hmac_secretkey_attrs,
				   ARRAY_SIZE(hmac_secretkey_attrs),
				   &hmac_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize message sign operation\n");
	ret = pfunc->C_MessageSignInit(sess, &sign_verify_mech,
				       hmac_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, NULL_PTR, 0, signature,
				   &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignMessage"))
		goto end;

	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Message sign\n");
	ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, msg, msg_len, signature,
				   &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignMessage"))
		goto end;

	TEST_OUT("Initialize message verify operation\n");
	ret = pfunc->C_MessageVerifyInit(sess, &sign_verify_mech,
					 hmac_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Message verify signature\n");
	ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, msg, msg_len, signature,
				     signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyMessage"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_hmac_plaintext_key(CK_FUNCTION_LIST_3_0_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech[] = { { .mechanism = CKM_SHA256_HMAC },
					    { .mechanism = CKM_SHA384_HMAC } };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hmac_hsecretkey = 0;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_KEY_TYPE secret_key_type[] = { CKK_SHA256_HMAC, CKK_SHA384_HMAC };
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_HMAC,
						 CKM_SHA384_HMAC };
	CK_MECHANISM_TYPE allowed_mech = CKM_NULL;
	CK_BYTE_PTR keys[] = { key_256, key_384 };
	CK_ULONG keys_size[] = { sizeof(key_256), sizeof(key_384) };
	CK_BYTE_PTR signatures[] = { hmac_256, hmac_384 };
	CK_ULONG signatures_len[] = { sizeof(hmac_256), sizeof(hmac_384) };

	CK_ATTRIBUTE hmac_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_KEY_TYPE, &key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_VALUE, NULL_PTR, 0 },
		{ CKA_ALLOWED_MECHANISMS, &allowed_mech,
		  sizeof(CK_MECHANISM_TYPE) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session((CK_FUNCTION_LIST_PTR)pfunc, 0, &sess) ==
	    TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0]) ||
	    !util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[1])) {
		status = TEST_SKIP;
		goto end;
	}

	for (; i < ARRAY_SIZE(sign_verify_mech); i++) {
		hmac_secretkey_attrs[4].pValue = keys[i];
		hmac_secretkey_attrs[4].ulValueLen = keys_size[i];
		key_type = secret_key_type[i];
		allowed_mech = key_allowed_mech[i];

		TEST_OUT("Create HMAC secret Key\n");
		ret = pfunc->C_CreateObject(sess, hmac_secretkey_attrs,
					    ARRAY_SIZE(hmac_secretkey_attrs),
					    &hmac_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
			goto end;

		TEST_OUT("Initialize message sign operation\n");
		ret = pfunc->C_MessageSignInit(sess, &sign_verify_mech[i],
					       hmac_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
			goto end;

		TEST_OUT("Get signature length\n");
		ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, NULL_PTR, 0,
					   signature, &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_SignMessage"))
			goto end;

		signature = malloc(signature_len);
		if (CHECK_EXPECTED(signature, "Allocation error"))
			goto end;

		TEST_OUT("Message sign\n");
		ret = pfunc->C_SignMessage(sess, NULL_PTR, 0, data,
					   sizeof(data), signature,
					   &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_SignMessage"))
			goto end;

		if (!util_compare_buffers(signature, signature_len,
					  signatures[i], signatures_len[i])) {
			TEST_OUT("HMAC signature invalid\n");
			goto end;
		}

		TEST_OUT("Initialize message verify operation\n");
		ret = pfunc->C_MessageVerifyInit(sess, &sign_verify_mech[i],
						 hmac_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
			goto end;

		TEST_OUT("Message verify signature\n");
		ret = pfunc->C_VerifyMessage(sess, NULL_PTR, 0, data,
					     sizeof(data), signature,
					     signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyMessage"))
			goto end;

		free(signature);
		signature = NULL;
		signature_len = 0;
	}

	status = TEST_PASS;

end:
	util_close_session((CK_FUNCTION_LIST_PTR)pfunc, &sess);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_sign_verify_message(void *lib_hdl, CK_VOID_PTR pfunc)
{
	(void)lib_hdl;
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_C_INITIALIZE_ARGS init = { 0 };
	CK_VERSION_PTR version = &((CK_FUNCTION_LIST_3_0_PTR)pfunc)->version;

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START();

	if (CHECK_EXPECTED(version->major == 3 && version->minor == 1,
			   "Bad version expected %01d.%01d", version->major,
			   version->minor))
		goto end;

	ret = ((CK_FUNCTION_LIST_3_0_PTR)pfunc)->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (sign_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (verify_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (sign_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (verify_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_no_init(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multiple_init(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_cmac(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_hmac(pfunc) == TEST_FAIL)
		goto end;

	status = sign_verify_hmac_plaintext_key(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_3_0_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
