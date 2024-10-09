// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
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

	TEST_OUT("Destroy %sData\n", token ? "Token " : "");
	ret = pfunc->C_DestroyObject(sess, hdata);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
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

	TEST_OUT("Destroy %sData\n", token ? "Token " : "");
	ret = pfunc->C_DestroyObject(sess, hdata);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
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

	status = data_storage_store(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
