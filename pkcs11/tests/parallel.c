// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */
#include <stdlib.h>
#include <string.h>

#include "util_session.h"

static int parallel_check_legacy(CK_FUNCTION_LIST_PTR pfunc,
				 CK_SESSION_HANDLE_PTR sess)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;

	SUBTEST_START();

	TEST_OUT("Legacy functions return CKR_FUNCTION_NOT_PARALLEL\n");
	ret = pfunc->C_GetFunctionStatus(*sess);
	if (CHECK_CK_RV(CKR_FUNCTION_NOT_PARALLEL, "C_GetFunctionStatus"))
		goto end;

	ret = pfunc->C_CancelFunction(*sess);
	if (!CHECK_CK_RV(CKR_FUNCTION_NOT_PARALLEL, "C_CancelFunction"))
		status = TEST_PASS;

end:
	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_parallel(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	(void)lib_hdl;

	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	TEST_START();

	ret = pfunc->C_Initialize(NULL);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_ro_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	status = parallel_check_legacy(pfunc, &sess);

end:
	util_close_session(pfunc, &sess);

	ret = pfunc->C_Finalize(NULL);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
