// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "local.h"
#include "os_mutex.h"
#include "util_session.h"

static int data_storage_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BBOOL token = CK_TRUE;
	CK_UTF8CHAR label[] = "Data";
	CK_BYTE data[] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE retrieved_data[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
	CK_ATTRIBUTE data_template[] = {
		{ CKA_CLASS, &data_class, sizeof(data_class) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, data, sizeof(data) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) }
	};
	CK_ATTRIBUTE retrieve_template[] = { { CKA_VALUE, retrieved_data,
					       sizeof(retrieved_data) } };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_CreateObject(0, data_template, ARRAY_SIZE(data_template),
				    &hdata);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_CreateObject"))
		goto end;

	TEST_OUT("Check data pointer NULL\n");
	data_template[2].pValue = NULL_PTR;

	ret = pfunc->C_CreateObject(sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (CHECK_CK_RV(CKR_ATTRIBUTE_VALUE_INVALID, "C_CreateObject"))
		goto end;

	TEST_OUT("Check data length 0\n");
	data_template[2].pValue = data;
	data_template[2].ulValueLen = 0;

	ret = pfunc->C_CreateObject(sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (CHECK_CK_RV(CKR_ATTRIBUTE_VALUE_INVALID, "C_CreateObject"))
		goto end;

	TEST_OUT("Create %sData\n", token ? "Token " : "");
	data_template[2].ulValueLen = sizeof(data);
	ret = pfunc->C_CreateObject(sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Retrieve %sData, buffer too small\n", token ? "Token " : "");
	ret = pfunc->C_GetAttributeValue(sess, hdata, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetAttributeValue"))
		goto end;

	if (retrieve_template[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
		TEST_OUT("Wrong Data length: got %ld, expected %ld\n",
			 retrieve_template[0].ulValueLen,
			 CK_UNAVAILABLE_INFORMATION);
		goto end;
	}

	TEST_OUT("Retrieve %sData, pointer NULL\n", token ? "Token " : "");
	retrieve_template[0].pValue = NULL_PTR;
	ret = pfunc->C_GetAttributeValue(sess, hdata, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (retrieve_template[0].ulValueLen != sizeof(data)) {
		TEST_OUT("Wrong Data length: got %ld, expected %ld\n",
			 retrieve_template[0].ulValueLen,
			 (unsigned long)sizeof(data));
		goto end;
	}

	status = TEST_PASS;

end:
	if (hdata != CK_INVALID_HANDLE) {
		TEST_OUT("Destroy %sData\n", token ? "Token " : "");
		ret = pfunc->C_DestroyObject(sess, hdata);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int data_storage_store(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BBOOL token = CK_TRUE;
	CK_UTF8CHAR label[] = "Data";
	CK_BYTE data[] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE retrieved_data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	CK_BYTE obj_id[] = { 0x2A, 0x82, 0x80, 0x80, 0xC0, 0x03 };
	CK_BYTE retrieved_obj_id[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	CK_ATTRIBUTE data_template[] = {
		{ CKA_CLASS, &data_class, sizeof(data_class) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, data, sizeof(data) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_OBJECT_ID, &obj_id, sizeof(obj_id) }
	};
	CK_ATTRIBUTE retrieve_template[] = {
		{ CKA_VALUE, retrieved_data, sizeof(retrieved_data) },
		{ CKA_OBJECT_ID, retrieved_obj_id, sizeof(retrieved_obj_id) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Create %sData\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Retrieve %sData\n", token ? "Token " : "");
	ret = pfunc->C_GetAttributeValue(sess, hdata, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (!util_compare_buffers(data, sizeof(data),
				  retrieve_template[0].pValue,
				  retrieve_template[0].ulValueLen)) {
		TEST_OUT("Retrieved Data is not the same\n");
		goto end;
	}

	if (!util_compare_buffers(obj_id, sizeof(obj_id),
				  retrieve_template[1].pValue,
				  retrieve_template[1].ulValueLen)) {
		TEST_OUT("Retrieved Object ID is not the same\n");
		goto end;
	}

	TEST_OUT("Destroy %sData\n", token ? "Token " : "");
	ret = pfunc->C_DestroyObject(sess, hdata);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Create %sData, no ID\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(sess, data_template,
				    ARRAY_SIZE(data_template) - 1, &hdata);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Retrieve %sData\n", token ? "Token " : "");
	ret = pfunc->C_GetAttributeValue(sess, hdata, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (!util_compare_buffers(data, sizeof(data),
				  retrieve_template[0].pValue,
				  retrieve_template[0].ulValueLen)) {
		TEST_OUT("Retrieved Data is not the same\n");
		goto end;
	}

	if (util_compare_buffers(obj_id, sizeof(obj_id),
				 retrieve_template[1].pValue,
				 retrieve_template[1].ulValueLen)) {
		TEST_OUT("Retrieved Object ID is incorrect\n");
		goto end;
	}

	status = TEST_PASS;

end:
	if (hdata != CK_INVALID_HANDLE) {
		TEST_OUT("Destroy %sData\n", token ? "Token " : "");
		ret = pfunc->C_DestroyObject(sess, hdata);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int data_storage_store_specific_oid(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BBOOL token = CK_TRUE;
	CK_UTF8CHAR label[] = "Data";
	CK_BYTE data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	CK_BYTE retrieved_data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	CK_BYTE obj_id[] = { 0x2a, 0x00 };
	CK_BYTE retrieved_obj_id[] = { 0x00, 0x00 };
	CK_ATTRIBUTE data_template[] = {
		{ CKA_CLASS, &data_class, sizeof(data_class) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, data, sizeof(data) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_OBJECT_ID, &obj_id, sizeof(obj_id) }
	};
	CK_ATTRIBUTE find_template[] = {
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_OBJECT_ID, &obj_id, sizeof(obj_id) }
	};
	CK_ATTRIBUTE retrieve_template[] = {
		{ CKA_VALUE, retrieved_data, sizeof(retrieved_data) },
		{ CKA_OBJECT_ID, retrieved_obj_id, sizeof(retrieved_obj_id) }
	};
	CK_ULONG nb_match = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Create %sData\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Find Data\n");
	ret = pfunc->C_FindObjectsInit(sess, find_template,
				       ARRAY_SIZE(find_template));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hdata, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	TEST_OUT("Retrieve %sData\n", token ? "Token " : "");
	ret = pfunc->C_GetAttributeValue(sess, hdata, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (!util_compare_buffers(data, sizeof(data),
				  retrieve_template[0].pValue,
				  retrieve_template[0].ulValueLen)) {
		TEST_OUT("Retrieved Data is not the same\n");
		goto end;
	}

	if (!util_compare_buffers(obj_id, sizeof(obj_id),
				  retrieve_template[1].pValue,
				  retrieve_template[1].ulValueLen)) {
		TEST_OUT("Retrieved Object ID is not the same\n");
		goto end;
	}

	status = TEST_PASS;

end:
	if (hdata != CK_INVALID_HANDLE) {
		TEST_OUT("Destroy %sData\n", token ? "Token " : "");
		ret = pfunc->C_DestroyObject(sess, hdata);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_data_storage(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (data_storage_bad_param(pfunc) == TEST_FAIL)
		goto end;

	if (data_storage_store(pfunc) == TEST_FAIL)
		goto end;

	status = data_storage_store_specific_oid(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
