// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <pkcs11smw.h>
#include <pkcs11smw_config.h>

#include "config.h"
#include "tests_pkcs11.h"
#include "local.h"
#include "os_mutex.h"

/* Declaration of the overall tests result */
struct tests_result tests_result;

static void *open_lib(const char *libname)
{
	void *handle = NULL;

#ifdef SMW_CONFIG_FILE
	int err;
	int errnum;
	char env_config[1024];

	strcpy(env_config, SMW_CONFIG_FILE);
	printf("SMW_CONFIG_FILE=%s\n", env_config);
	err = setenv("SMW_CONFIG_FILE", env_config, 1);
	if (__errno_location()) {
		errnum = errno;
		(void)CHECK_EXPECTED(!err, "Set Environment error: %s\n",
				     strerror(errnum));
	} else {
		(void)CHECK_EXPECTED(!err, "Set Environment error\n");
	}
#else
	char *env_config;

	env_config = getenv("SMW_CONFIG_FILE");
	printf("SMW_CONFIG_FILE=%s\n", env_config);
#endif

	handle = dlopen(libname, RTLD_LAZY);
	(void)CHECK_EXPECTED(handle, "%s\n", dlerror());

	return handle;
}

static CK_FUNCTION_LIST_PTR get_function_list(void *handle)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	CK_FUNCTION_PTR(C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR pfunc = NULL;

	/* First get the function symbol */
	C_GetFunctionList = dlsym(handle, "C_GetFunctionList");
	if (CHECK_EXPECTED(C_GetFunctionList,
			   "Symbol C_GetFunctionList - error %s\n", dlerror()))
		goto end;

	ret = C_GetFunctionList(&pfunc);
	if (CHECK_CK_RV(CKR_OK, "C_GetFunctionList"))
		goto end;

	TEST_OUT("Function list version is %01d.%01d\n", pfunc->version.major,
		 pfunc->version.minor);

end:
	if (ret == CKR_OK)
		return pfunc;

	return NULL;
}

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

static void close_lib(void *handle)
{
	dlclose(handle);
}

static void tests_pkcs11_get_functions(void *lib_hdl,
				       CK_FUNCTION_LIST_PTR_PTR pfunc)
{
	int status;

	TEST_START(status);

	*pfunc = get_function_list(lib_hdl);
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
	TEST_DEF(get_info_ifs), TEST_DEF(get_ifs), TEST_DEF(initialize),
	TEST_DEF(slot_token),	TEST_DEF(session), TEST_DEF(object),
	TEST_DEF(find),
};

void tests_pkcs11_list(void)
{
	printf("PKCS#11 List of tests:\n");
	for (unsigned int id = 0; id < ARRAY_SIZE(test_list); id++)
		printf("\t %s\n", test_list[id].name);

	printf("\n");
}

int tests_pkcs11(char *test_name)
{
	int diff_count;
	void *lib_hdl;
	CK_FUNCTION_LIST_PTR func_list;

	/* Initialize tests result */
	memset(&tests_result, 0, sizeof(tests_result));

	printf("Lib %s\n", DEFAULT_PKCS11_LIB);

	lib_hdl = open_lib(DEFAULT_PKCS11_LIB);
	if (!lib_hdl)
		return -1;

	tests_pkcs11_get_functions(lib_hdl, &func_list);
	if (func_list) {
		for (unsigned int id = 0; id < ARRAY_SIZE(test_list); id++) {
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
	TEST_OUT("| Ran %d tests with %d failures\n", tests_result.count,
		 tests_result.count_fail);

	diff_count = tests_result.count - tests_result.count_pass -
		     tests_result.count_fail;
	if (diff_count)
		TEST_OUT("| Total tests %d != %d PASSED + %d FAILED\n",
			 tests_result.count, tests_result.count_pass,
			 tests_result.count_fail);

	TEST_OUT("|_______________________________\n");
	TEST_OUT("\n");

	if (lib_hdl)
		close_lib(lib_hdl);

	if (diff_count || tests_result.count_fail)
		return -1;

	return 0;
}
