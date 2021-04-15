// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */
#include <string.h>

#include <pkcs11smw_config.h>

#include "tests_pkcs11.h"
#include "local.h"
#include "os_mutex.h"
#include "util_lib.h"

/* Declaration of the global tests data */
struct tests_data tests_data;

static int initialize(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_C_INITIALIZE_ARGS init = { 0 };

	SUBTEST_START(status);

	TEST_OUT("param = NULL\n");
	ret = pfunc->C_Initialize(NULL);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;
	ret = pfunc->C_Finalize(NULL);

	TEST_OUT("\nparam = empty\n");
	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;
	ret = pfunc->C_Finalize(NULL);

	TEST_OUT("\nparam = empty\n");
	TEST_OUT("flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS\n");
	init.flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS;
	ret = pfunc->C_Initialize(&init);
#ifdef PKCS11_MULTI_THREAD
	if (CHECK_CK_RV(CKR_NEED_TO_CREATE_THREADS, "C_Initialize"))
		goto end;
#else
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;
#endif
	ret = pfunc->C_Finalize(NULL);

	TEST_OUT("\nparam = empty\n");
	TEST_OUT("flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS\n");
	TEST_OUT("        CKF_OS_LOCKING_OK\n");
	init.flags |= CKF_OS_LOCKING_OK;
	ret = pfunc->C_Initialize(&init);
#ifdef PKCS11_MULTI_THREAD
	if (CHECK_CK_RV(CKR_NEED_TO_CREATE_THREADS, "C_Initialize"))
		goto end;
#else
#ifdef PKCS11_OS_MUTEX_SUPPORT
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;
#else
	if (CHECK_CK_RV(CKR_CANT_LOCK, "C_Initialize"))
		goto end;
#endif /* PKCS11_OS_MUTEX_SUPPORT */
#endif /* PKCS11_MULTI_THREAD */
	ret = pfunc->C_Finalize(NULL);

	TEST_OUT("\nparam = empty\n");
	TEST_OUT("flags = CKF_OS_LOCKING_OK\n");
	init.flags = CKF_OS_LOCKING_OK;
	ret = pfunc->C_Initialize(&init);
#ifdef PKCS11_OS_MUTEX_SUPPORT
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;
#else
	if (CHECK_CK_RV(CKR_CANT_LOCK, "C_Initialize"))
		goto end;
#endif /* PKCS11_OS_MUTEX_SUPPORT */
	ret = pfunc->C_Finalize(NULL);

	TEST_OUT("\nparam = CreateMutex defined\n");
	TEST_OUT("flags = CKF_OS_LOCKING_OK\n");
	init.CreateMutex = (CK_CREATEMUTEX)(-1);
	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Initialize"))
		goto end;
	ret = pfunc->C_Finalize(NULL);

	TEST_OUT("\nparam = All defined\n");
	TEST_OUT("flags = CKF_OS_LOCKING_OK\n");
	init.CreateMutex = mutex_create_empty;
	init.DestroyMutex = mutex_destroy_empty;
	init.LockMutex = mutex_lock_empty;
	init.UnlockMutex = mutex_unlock_empty;
	ret = pfunc->C_Initialize(&init);
	(void)CHECK_CK_RV(CKR_OK, "C_Initialize");

	status = TEST_PASS;
end:
	ret = pfunc->C_Finalize(NULL);

	SUBTEST_END(status);

	return status;
}

static void tests_pkcs11_get_functions(void *lib_hdl,
				       CK_FUNCTION_LIST_PTR_PTR pfunc)
{
	int status;

	TEST_START(status);

	*pfunc = util_lib_get_func_list(lib_hdl);
	if (!CHECK_EXPECTED(*pfunc, "Get function failure"))
		status = TEST_PASS;

	TEST_END(status);
}

static void tests_pkcs11_initialize(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	(void)lib_hdl;
	int status;

	TEST_START(status);

	status = initialize(pfunc);

	TEST_END(status);
}

struct test_def {
	const char *name;
	void (*test)(void *handle, CK_FUNCTION_LIST_PTR func_list);
};

#define TEST_DEF(name)                                                         \
	{                                                                      \
#name, tests_pkcs11_##name,                                    \
	}

struct test_def test_list[] = {
	TEST_DEF(get_info_ifs),
	TEST_DEF(get_ifs),
	TEST_DEF(initialize),
	TEST_DEF(slot_token),
	TEST_DEF(session),
	TEST_DEF(object_key_ec),
	TEST_DEF(object_key_cipher),
	TEST_DEF(object_key_rsa),
	TEST_DEF(find),
	TEST_DEF(parallel),
	TEST_DEF(callback),
	TEST_DEF(digest),
	TEST_DEF(sign_verify),
	TEST_DEF(random),
};

void tests_pkcs11_list(void)
{
	TEST_OUT("PKCS#11 List of tests:\n");
	for (unsigned int id = 0; id < ARRAY_SIZE(test_list); id++)
		TEST_OUT("\t %s\n", test_list[id].name);

	TEST_OUT("\n");
}

int tests_pkcs11(char *test_name)
{
	int diff_count;
	void *lib_hdl;
	CK_FUNCTION_LIST_PTR func_list;

	/* Initialize tests result */
	memset(&tests_data, 0, sizeof(tests_data));

	lib_hdl = util_lib_open(NULL);
	if (!lib_hdl)
		return -1;

	tests_pkcs11_get_functions(lib_hdl, &func_list);
	if (func_list) {
		for (unsigned int id = 0; id < ARRAY_SIZE(test_list); id++) {
			tests_data.trace_pid = 0;
			if (test_name) {
				if (!strcmp(test_name, test_list[id].name)) {
					test_list[id].test(lib_hdl, func_list);
					break;
				}
			} else {
				test_list[id].test(lib_hdl, func_list);
			}
		}
	}

	TEST_OUT("\n");
	TEST_OUT(" _______________________________\n");
	TEST_OUT("|\n");
	TEST_OUT("| Ran %d tests with %d failures\n", tests_data.result.count,
		 tests_data.result.count_fail);

	diff_count = tests_data.result.count - tests_data.result.count_pass -
		     tests_data.result.count_fail;
	if (diff_count)
		TEST_OUT("| Total tests %d != %d PASSED + %d FAILED\n",
			 tests_data.result.count, tests_data.result.count_pass,
			 tests_data.result.count_fail);

	TEST_OUT("|_______________________________\n");
	TEST_OUT("\n");

	util_lib_close(lib_hdl);

	if (diff_count || tests_data.result.count_fail)
		return -1;

	return 0;
}
