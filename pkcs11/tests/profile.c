// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <smw_status.h>
#include <smw/object.h>

#include "os_mutex.h"
#include "util_session.h"

#define MAX_OBJ_COUNT	  3
#define PROFILE_OBJ_COUNT 1

static int find_profile_object(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;

	CK_ULONG nb_match = 0;
	CK_BBOOL ck_true = CK_TRUE;
	unsigned int i = 0;

	CK_OBJECT_CLASS profile_class = CKO_PROFILE;
	CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
	CK_PROFILE_ID profile_id = CKP_INVALID_ID;
	CK_ATTRIBUTE find_token_profile_objects[] = {
		{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
		{ CKA_CLASS, &profile_class, sizeof(profile_class) },
	};
	CK_ATTRIBUTE retrieve_template = { CKA_PROFILE_ID, &profile_id,
					   sizeof(profile_id) };
	CK_OBJECT_HANDLE profile_obj_hdl[PROFILE_OBJ_COUNT] = { 0 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Find profile objects\n");
	ret = pfunc->C_FindObjectsInit(sess, find_token_profile_objects,
				       ARRAY_SIZE(find_token_profile_objects));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, profile_obj_hdl, PROFILE_OBJ_COUNT,
				   &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	if (CHECK_EXPECTED(nb_match == PROFILE_OBJ_COUNT,
			   "Got %lu but expected %d object", nb_match,
			   PROFILE_OBJ_COUNT))
		goto end;

	TEST_OUT("Number of match found : %lu\n", nb_match);

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	TEST_OUT("Get CKA_PROFILE_ID\n");
	for (; i < nb_match; i++) {
		ret = pfunc->C_GetAttributeValue(sess, profile_obj_hdl[i],
						 &retrieve_template, 1);
		if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
			goto end;

		TEST_OUT("Profile ID = %lu\n", profile_id);
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int find_all_objects(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;

	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;
	CK_ULONG key_len = 16;
	CK_ULONG nb_match = 0;
	unsigned int i = 0;

	CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE token_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE session_key = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_ECB };
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
	CK_PROFILE_ID profile_id = CKP_INVALID_ID;
	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
		{ CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE retrieve_profile_id = { CKA_PROFILE_ID, &profile_id,
					     sizeof(profile_id) };
	CK_ATTRIBUTE retrieve_obj_class = { CKA_CLASS, &obj_class,
					    sizeof(obj_class) };

	CK_OBJECT_HANDLE object_handles[MAX_OBJ_COUNT] = { 0 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate AES token key\n");
	ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), &token_key);

	key_attrs[1].pValue = &ck_false;

	TEST_OUT("Generate AES session key\n");
	ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), &session_key);

	TEST_OUT("Find all objects\n");
	ret = pfunc->C_FindObjectsInit(sess, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, object_handles, MAX_OBJ_COUNT,
				   &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 3, "Got %lu but expected %d object",
			   nb_match, MAX_OBJ_COUNT))
		goto end;

	TEST_OUT("Number of match found : %lu\n", nb_match);

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	for (; i < nb_match; i++) {
		TEST_OUT("Retrieve object class\n");
		ret = pfunc->C_GetAttributeValue(sess, object_handles[i],
						 &retrieve_obj_class, 1);
		if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
			goto end;

		TEST_OUT("Object class = %lu\n", obj_class);

		if (obj_class != CKO_PROFILE)
			continue;

		TEST_OUT("Retrieve Profile ID\n");
		ret = pfunc->C_GetAttributeValue(sess, object_handles[i],
						 &retrieve_profile_id, 1);
		if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
			goto end;

		TEST_OUT("Profile ID = %lu\n", profile_id);
	}

	status = TEST_PASS;

end:
	TEST_OUT("Key Destroy #%lu\n", token_key);
	if (token_key != CK_INVALID_HANDLE) {
		ret = pfunc->C_DestroyObject(sess, token_key);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_object_profile(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (find_profile_object(pfunc) == TEST_FAIL)
		goto end;

	if (find_all_objects(pfunc) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
