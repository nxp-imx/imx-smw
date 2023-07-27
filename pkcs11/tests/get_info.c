// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "local.h"

static const char def_if_name[] = "PKCS 11";
static const char unknown_if_name[] = "UNKNOWN";

#define IF_DEF 0
#define IF_V3  1

static struct test_interface {
	const char *name;
	CK_VERSION version;
	CK_ULONG flags;
} exp_ifs[] = {
	{
		.name = def_if_name,
		.version = { 2, 40 },
		.flags = 0,
	},
	{
		.name = def_if_name,
		.version = { 3, 0 },
		.flags = 0,
	},
};

static int get_info(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_INFO info = { 0 };

	SUBTEST_START();

	ret = pfunc->C_GetInfo(&info);
	if (CHECK_CK_RV(CKR_OK, "C_GetInfo"))
		goto end;

	TEST_OUT("\n\nInformation:\n");
	TEST_OUT("\tInterface version:  %01d.%01d\n",
		 info.cryptokiVersion.major, info.cryptokiVersion.minor);
	TEST_OUT("\tmanufacturer:       %.*s!\n",
		 (int)sizeof(info.manufacturerID), info.manufacturerID);
	TEST_OUT("\tflags:              0x%lX\n", info.flags);
	TEST_OUT("\tlibraryDescription: %.*s!\n",
		 (int)sizeof(info.libraryDescription), info.libraryDescription);
	TEST_OUT("\tlibraryVersion:     %01d.%01d\n", info.libraryVersion.major,
		 info.libraryVersion.minor);

	status = TEST_PASS;
end:
	SUBTEST_END(status);
	return status;
}

static int get_interface_list(void *handle)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;

	CK_FUNCTION_PTR(C_GetInterfaceList)
	(CK_INTERFACE_PTR, CK_ULONG_PTR) = NULL;
	CK_ULONG nb_ifs = 0;
	CK_INTERFACE_PTR ifs = NULL;
	CK_FUNCTION_LIST_PTR funcs = NULL_PTR;
	CK_ULONG idx = 0;
	int retcmp = 0;

	SUBTEST_START();

	/*
	 * The C_GetInterfaceList function is not part of the
	 * CK_FUNCTION_LIST, it's part of the CK_FUNCTION_LIST_3_0.
	 * As the get_function_list returns a CK_FUNCTION_LIST pointer,
	 * we need to get the function symbol to setup the function
	 * pointer.
	 */
	C_GetInterfaceList = dlsym(handle, "C_GetInterfaceList");
	if (CHECK_EXPECTED(C_GetInterfaceList,
			   "Symbol C_GetInterfaceList - error %s\n", dlerror()))
		goto end;

	TEST_OUT("Check all parameters NULL\n");
	ret = C_GetInterfaceList(NULL, NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetInterfaceList"))
		goto end;

	TEST_OUT("\nGet number of interfaces\n");
	ret = C_GetInterfaceList(NULL, &nb_ifs);
	if (CHECK_CK_RV(CKR_OK, "C_GetInterfaceList"))
		goto end;

	if (CHECK_EXPECTED(nb_ifs == ARRAY_SIZE(exp_ifs),
			   "Got %lu but expected %zu interfaces", nb_ifs,
			   ARRAY_SIZE(exp_ifs)))
		goto end;

	ifs = malloc(nb_ifs * sizeof(CK_INTERFACE));
	if (CHECK_EXPECTED(ifs, "Allocation error"))
		goto end;

	nb_ifs--;
	TEST_OUT("\nCheck too small number (%lu vs %lu)\n", nb_ifs, nb_ifs + 1);
	ret = C_GetInterfaceList(ifs, &nb_ifs);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetInterfaceList"))
		goto end;

	nb_ifs++;
	TEST_OUT("\nGet all interfaces\n");
	ret = C_GetInterfaceList(ifs, &nb_ifs);
	if (CHECK_CK_RV(CKR_OK, "C_GetInterfaceList"))
		goto end;

	for (idx = 0; idx < nb_ifs; idx++) {
		funcs = (CK_FUNCTION_LIST_PTR)ifs[idx].pFunctionList;

		TEST_OUT("\nInterface #%lu - %s\n", idx,
			 ifs[idx].pInterfaceName);
		TEST_OUT("\tVersion %01d.%01d\n", funcs->version.major,
			 funcs->version.minor);
		TEST_OUT("\tFunctions %p\n", ifs[idx].pFunctionList);
		TEST_OUT("\tFlags 0x%lX\n", ifs[idx].flags);

		retcmp = strcmp((const char *)ifs[idx].pInterfaceName,
				exp_ifs[idx].name);
		if (CHECK_EXPECTED(retcmp == 0, "Bad name expected %s",
				   exp_ifs[idx].name))
			goto end;

		if (CHECK_EXPECTED(funcs->version.major ==
						   exp_ifs[idx].version.major &&
					   funcs->version.minor ==
						   exp_ifs[idx].version.minor,
				   "Bad version expected %01d.%01d",
				   exp_ifs[idx].version.major,
				   exp_ifs[idx].version.minor))
			goto end;
	}

	status = TEST_PASS;
end:
	if (ifs)
		free(ifs);

	SUBTEST_END(status);

	return status;
}

static int get_interface(void *handle)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;

	CK_FUNCTION_PTR(C_GetInterface)
	(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
	 CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags) = NULL;
	CK_INTERFACE_PTR ifs = NULL;
	struct test_interface *def_if = &exp_ifs[IF_DEF];
	CK_FUNCTION_LIST_PTR funcs = NULL_PTR;
	CK_VERSION bad_ver = { 2, 10 };
	int retcmp = 0;

	SUBTEST_START();

	/*
	 * The C_GetInterface function is not part of the
	 * CK_FUNCTION_LIST, it's part of the CK_FUNCTION_LIST_3_0.
	 * As the get_function_list returns a CK_FUNCTION_LIST pointer,
	 * we need to get the function symbol to setup the function
	 * pointer.
	 */
	C_GetInterface = dlsym(handle, "C_GetInterface");
	if (CHECK_EXPECTED(C_GetInterface, "Symbol C_GetInterface - error %s\n",
			   dlerror()))
		goto end;

	TEST_OUT("Check all parameters NULL\n");
	ret = C_GetInterface(NULL, NULL, NULL, 0);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetInterface"))
		goto end;

	TEST_OUT("\nCheck bad parameter: name\n");
	ret = C_GetInterface((CK_UTF8CHAR_PTR)unknown_if_name, NULL, &ifs, 0);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetInterface"))
		goto end;

	if (CHECK_EXPECTED(!ifs, "Interface returned must be NULL"))
		goto end;

	TEST_OUT("\nCheck good name bad parameter: version\n");
	ret = C_GetInterface((CK_UTF8CHAR_PTR)def_if_name, &bad_ver, &ifs, 0);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetInterface"))
		goto end;

	if (CHECK_EXPECTED(!ifs, "Interface returned must be NULL"))
		goto end;

	TEST_OUT("\nCheck flag parameter\n");
	ret = C_GetInterface((CK_UTF8CHAR_PTR)def_if_name, &def_if->version,
			     &ifs, 0x10);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetInterface"))
		goto end;

	if (CHECK_EXPECTED(!ifs, "Interface returned msut be NULL"))
		goto end;

	TEST_OUT("\nCheck flag parameter\n");
	ret = C_GetInterface(NULL, NULL, &ifs, 0x10);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetInterface"))
		goto end;

	if (CHECK_EXPECTED(!ifs, "Interface returned msut be NULL"))
		goto end;

	TEST_OUT("\nCheck not critera - Get default interface\n");
	ret = C_GetInterface(NULL, NULL, &ifs, 0);
	if (CHECK_CK_RV(CKR_OK, "C_GetInterface"))
		goto end;

	if (CHECK_EXPECTED(ifs, "Interface returned is NULL"))
		goto end;

	funcs = (CK_FUNCTION_LIST_PTR)ifs->pFunctionList;

	TEST_OUT("\nInterface %s\n", ifs->pInterfaceName);
	TEST_OUT("\tVersion %01d.%01d\n", funcs->version.major,
		 funcs->version.minor);
	TEST_OUT("\tFunctions %p\n", ifs->pFunctionList);
	TEST_OUT("\tFlags 0x%lX\n", ifs->flags);

	retcmp = strcmp((const char *)ifs->pInterfaceName, def_if->name);
	if (CHECK_EXPECTED(retcmp == 0, "Bad name expected %s", def_if->name))
		goto end;

	if (CHECK_EXPECTED((funcs->version.major == def_if->version.major &&
			    funcs->version.minor == def_if->version.minor),
			   "Bad version expected %01d.%01d",
			   def_if->version.major, def_if->version.minor))
		goto end;

	TEST_OUT("\nGet interface v3.0\n");
	ret = C_GetInterface(NULL, &exp_ifs[IF_V3].version, &ifs, 0);
	if (CHECK_CK_RV(CKR_OK, "C_GetInterface"))
		goto end;

	if (CHECK_EXPECTED(ifs, "Interface returned is NULL"))
		goto end;

	funcs = (CK_FUNCTION_LIST_PTR)ifs->pFunctionList;

	TEST_OUT("\nInterface %s\n", ifs->pInterfaceName);
	TEST_OUT("\tVersion %01d.%01d\n", funcs->version.major,
		 funcs->version.minor);
	TEST_OUT("\tFunctions %p\n", ifs->pFunctionList);
	TEST_OUT("\tFlags 0x%lX\n", ifs->flags);

	retcmp = strcmp((const char *)ifs->pInterfaceName, exp_ifs[IF_V3].name);
	if (CHECK_EXPECTED(retcmp == 0, "Bad name expected %s",
			   exp_ifs[IF_V3].name))
		goto end;

	if (!CHECK_EXPECTED(funcs->version.major ==
					    exp_ifs[IF_V3].version.major &&
				    funcs->version.minor ==
					    exp_ifs[IF_V3].version.minor,
			    "Bad version expected %01d.%01d",
			    exp_ifs[IF_V3].version.major,
			    exp_ifs[IF_V3].version.minor))
		status = TEST_PASS;

end:
	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_get_info_ifs(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	TEST_START();

	if (get_info(pfunc) == TEST_FAIL)
		goto end;

	status = get_interface_list(lib_hdl);

end:
	TEST_END(status);
}

void tests_pkcs11_get_ifs(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	(void)pfunc;
	int status = 0;

	TEST_START();

	status = get_interface(lib_hdl);

	TEST_END(status);
}
