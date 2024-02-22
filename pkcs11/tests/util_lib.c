// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2024 NXP
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "local.h"
#include "util_lib.h"

char *util_lib_get_strerror(void)
{
	if (__errno_location())
		return strerror(errno);

	return "error unknown";
}

void *util_lib_open(const char *libname)
{
	const char *open_lib = DEFAULT_PKCS11_LIB;
	void *handle = NULL;

#ifdef SMW_CONFIG_FILE
	int err;
	char env_config[1024];

	strcpy(env_config, SMW_CONFIG_FILE);
	TEST_OUT("SMW_CONFIG_FILE=%s\n", env_config);
	err = setenv("SMW_CONFIG_FILE", env_config, 1);
	(void)CHECK_EXPECTED(!err, "Set Environment error: %s\n",
			     util_lib_get_strerror());
#else
	char *env_config;

	env_config = getenv("SMW_CONFIG_FILE");
	TEST_OUT("SMW_CONFIG_FILE=%s\n", env_config);
#endif

	if (libname)
		open_lib = libname;

	TEST_OUT("Try to open library %s\n", open_lib);
	handle = dlopen(open_lib, RTLD_LAZY);
	(void)CHECK_EXPECTED(handle, "%s\n", dlerror());

	return handle;
}

void util_lib_close(void *handle)
{
	if (handle)
		dlclose(handle);
}

CK_FUNCTION_LIST_PTR util_lib_get_func_list(void *handle)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	CK_VERSION version_2_40 = { .major = 2, .minor = 40 };
	CK_VERSION version_3_0 = { .major = 3, .minor = 0 };
	CK_VERSION version = version_2_40;

	CK_FUNCTION_PTR(C_GetInterface)
	(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
	 CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags) = NULL_PTR;
	CK_INTERFACE_PTR ifs = NULL_PTR;

	CK_FUNCTION_PTR(C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR pfunc = NULL_PTR;

	C_GetInterface = dlsym(handle, "C_GetInterface");
	if (C_GetInterface) {
		version = version_3_0;
		ret = C_GetInterface(NULL_PTR, &version, &ifs, 0);
		if (ret != CKR_OK) {
			version = version_2_40;
			ret = C_GetInterface(NULL_PTR, &version, &ifs, 0);
		}

		if (ret == CKR_OK)
			pfunc = (CK_FUNCTION_LIST_PTR)ifs->pFunctionList;
	} else {
		C_GetFunctionList = dlsym(handle, "C_GetFunctionList");
		if (C_GetFunctionList)
			ret = C_GetFunctionList(&pfunc);
		else
			TEST_OUT("Symbol C_GetFunctionList - error %s\n",
				 dlerror());
	}

	if (ret == CKR_OK && pfunc && version.major == pfunc->version.major &&
	    version.minor == pfunc->version.minor) {
		TEST_OUT("Function list version is %01d.%01d\n",
			 pfunc->version.major, pfunc->version.minor);

		return pfunc;
	}

	return NULL_PTR;
}
