// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_session.h"

static int object_cipher_key(CK_FUNCTION_LIST_PTR pfunc, CK_BBOOL token,
			     CK_BBOOL bencrypt)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_BYTE key[32] = {};

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE, &key, sizeof(key) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &bencrypt, sizeof(bencrypt) },
	};

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create %sKey Secret key\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (bencrypt) {
		if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
			goto end;

		TEST_OUT("Key secret created #%lu\n", hkey);
	} else {
		if (CHECK_CK_RV(CKR_DEVICE_ERROR, "C_CreateObject"))
			goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_generate_cipher_key(CK_FUNCTION_LIST_PTR pfunc,
				      CK_BBOOL token, CK_BBOOL bencrypt)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_ULONG key_len = 16;

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &bencrypt, sizeof(bencrypt) },
	};

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate %sCipher key\n", token ? "Token " : "");
	ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), &hkey);

	if (bencrypt) {
		if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
			goto end;

		TEST_OUT("Key generated #%lu\n", hkey);
	} else {
		if (CHECK_CK_RV(CKR_DEVICE_ERROR, "C_GenerateKey"))
			goto end;
	}

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_attribute_cipher_key(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx = 0;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_BYTE key[32] = {};
	CK_BBOOL btrue = true;
	CK_BBOOL bfalse = false;
	CK_BBOOL bvalue;

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE, &key, sizeof(key) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_DECRYPT, &btrue, sizeof(btrue) },
	};

	CK_ATTRIBUTE getkeyAttr[] = {
		{ CKA_CLASS, NULL_PTR, 0 },
		{ CKA_KEY_TYPE, NULL_PTR, 0 },
		{ CKA_VALUE, NULL_PTR, 0 },
	};

	CK_ATTRIBUTE setkeyAttrBad[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
	};

	CK_ATTRIBUTE keyAttrSensitive[] = {
		{ CKA_SENSITIVE, &btrue, sizeof(btrue) },
	};

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create Key Secret key\n");
	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key secret created #%lu\n", hkey);

	TEST_OUT("Get Key value - Return SENSITIVE error\n");
	ret = pfunc->C_GetAttributeValue(sess, hkey, getkeyAttr,
					 ARRAY_SIZE(getkeyAttr));
	if (CHECK_CK_RV(CKR_ATTRIBUTE_SENSITIVE, "C_GetAttributeValue"))
		goto end;

	if (CHECK_EXPECTED(getkeyAttr[2].ulValueLen ==
				   CK_UNAVAILABLE_INFORMATION,
			   "Got Secret key length=%lu exptected %#lx",
			   getkeyAttr[2].ulValueLen,
			   CK_UNAVAILABLE_INFORMATION))
		goto end;

	for (idx = 0; idx < ARRAY_SIZE(getkeyAttr) - 1; idx++) {
		if (CHECK_EXPECTED(getkeyAttr[idx].ulValueLen,
				   "Bad attribute #%lu length", idx))
			goto end;

		getkeyAttr[idx].pValue = calloc(1, getkeyAttr[idx].ulValueLen);
		if (CHECK_EXPECTED(getkeyAttr[idx].pValue,
				   "Allocation attribute #%lu", idx))
			goto end;
	}

	TEST_OUT("Get Key all key attributes\n");
	ret = pfunc->C_GetAttributeValue(sess, hkey, getkeyAttr,
					 ARRAY_SIZE(getkeyAttr) - 1);
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (CHECK_EXPECTED(*(CK_OBJECT_CLASS *)getkeyAttr[0].pValue ==
				   key_class,
			   "Got class %#lx exptected %#lx",
			   *(CK_OBJECT_CLASS *)getkeyAttr[0].pValue, key_class))
		goto end;

	if (CHECK_EXPECTED(*(CK_KEY_TYPE *)getkeyAttr[1].pValue == key_type,
			   "Got key type %#lx exptected %#lx",
			   *(CK_KEY_TYPE *)getkeyAttr[1].pValue, key_type))
		goto end;

	TEST_OUT("Set new Key class - error READ ONLY\n");
	ret = pfunc->C_SetAttributeValue(sess, hkey, setkeyAttrBad,
					 ARRAY_SIZE(setkeyAttrBad));
	if (CHECK_CK_RV(CKR_ATTRIBUTE_READ_ONLY, "C_SetAttributeValue"))
		goto end;

	TEST_OUT("Toggle sensitive attribute -> true\n");
	ret = pfunc->C_SetAttributeValue(sess, hkey, keyAttrSensitive,
					 ARRAY_SIZE(keyAttrSensitive));
	if (CHECK_CK_RV(CKR_OK, "C_SetAttributeValue"))
		goto end;

	TEST_OUT("Toggle sensitive attribute -> false - error READ ONLY\n");
	keyAttrSensitive[0].pValue = &bfalse;
	ret = pfunc->C_SetAttributeValue(sess, hkey, keyAttrSensitive,
					 ARRAY_SIZE(keyAttrSensitive));
	if (CHECK_CK_RV(CKR_ATTRIBUTE_READ_ONLY, "C_SetAttributeValue"))
		goto end;

	TEST_OUT("Get sensitive attribute\n");
	bvalue = false;
	keyAttrSensitive[0].pValue = &bvalue;
	ret = pfunc->C_GetAttributeValue(sess, hkey, keyAttrSensitive,
					 ARRAY_SIZE(keyAttrSensitive));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (CHECK_EXPECTED(bvalue, "Got key sensitive %d exptected %d", bvalue,
			   true))
		goto end;

	status = TEST_PASS;

end:
	for (idx = 0; idx < ARRAY_SIZE(getkeyAttr); idx++) {
		if (getkeyAttr[idx].pValue)
			free(getkeyAttr[idx].pValue);
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_object_key_cipher(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	(void)lib_hdl;
	int status;

	CK_RV ret;
	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START(status);

	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (object_cipher_key(pfunc, false, true) == TEST_FAIL)
		goto end;

	if (object_cipher_key(pfunc, false, false) == TEST_FAIL)
		goto end;

	if (object_generate_cipher_key(pfunc, false, true) == TEST_FAIL)
		goto end;

	if (object_generate_cipher_key(pfunc, false, false) == TEST_FAIL)
		goto end;

	if (object_cipher_key(pfunc, true, true) == TEST_FAIL)
		goto end;

	if (object_cipher_key(pfunc, true, false) == TEST_FAIL)
		goto end;

	if (object_generate_cipher_key(pfunc, true, true) == TEST_FAIL)
		goto end;

	if (object_generate_cipher_key(pfunc, true, false) == TEST_FAIL)
		goto end;

	status = object_attribute_cipher_key(pfunc);

end:
	ret = pfunc->C_Finalize(NULL);

	TEST_END(status);
}
