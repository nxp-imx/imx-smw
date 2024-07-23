// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_session.h"

/* messagetosign */
static CK_BYTE msg[] = { 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
			 0x74, 0x6f, 0x73, 0x69, 0x67, 0x6e };

static CK_ULONG msg_len = 13;

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

	TEST_OUT("Check CKA_SIGN key flag\n");
	sign_mech.mechanism = CKM_AES_CMAC_GENERAL;
	ret = pfunc->C_MessageSignInit(sess, &sign_mech,
				       aes_hsecretkey_not_permitted);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Check bad MAC mechanism parameters\n");
	sign_mech.pParameter = &mac_params;
	sign_mech.ulParameterLen = sizeof(mac_params);
	ret = pfunc->C_MessageSignInit(sess, &sign_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_MessageSignInit"))
		goto end;

	TEST_OUT("Check ignored MAC mechanism parameters\n");
	sign_mech.mechanism = CKM_AES_CMAC;
	ret = pfunc->C_MessageSignInit(sess, &sign_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageSignInit"))
		goto end;

	status = TEST_PASS;

end:
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

	TEST_OUT("Check invalid mechanism\n");
	verify_mech.mechanism = CKM_AES_KEY_GEN;
	ret = pfunc->C_MessageVerifyInit(sess, &verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Check CKA_VERIFY key flag\n");
	verify_mech.mechanism = CKM_AES_CMAC_GENERAL;
	ret = pfunc->C_MessageVerifyInit(sess, &verify_mech,
					 aes_hsecretkey_not_permitted);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Check bad MAC mechanism parameters\n");
	verify_mech.pParameter = &mac_params;
	verify_mech.ulParameterLen = sizeof(mac_params);
	ret = pfunc->C_MessageVerifyInit(sess, &verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_MessageVerifyInit"))
		goto end;

	TEST_OUT("Check ignored MAC mechanism parameters\n");
	verify_mech.mechanism = CKM_AES_CMAC;
	ret = pfunc->C_MessageVerifyInit(sess, &verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_MessageVerifyInit"))
		goto end;

	status = TEST_PASS;

end:
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

	status = sign_verify_hmac(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_3_0_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
