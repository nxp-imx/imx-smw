// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>

#include <smw_status.h>
#include <smw/object.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"

#define NS_TO_MILLISEC	   1000000u
#define SEC_TO_MILLISEC	   1000u
#define GENERATE_KEY_COUNT 50

#if !defined(ENABLE_DEBUG)
static int generate_cipher_key_performance(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM genmech = { .mechanism = CKM_DES_KEY_GEN };
	CK_OBJECT_HANDLE hkey[GENERATE_KEY_COUNT] = { CK_INVALID_HANDLE };
	CK_BBOOL btrue = CK_TRUE;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_DES_CBC };

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	unsigned int i = 0;
	struct timespec start = { 0 };
	struct timespec end = { 0 };
	unsigned long start_ms = 0;
	unsigned long end_ms = 0;
	unsigned long next_run = 0;
	unsigned long average = 0;
	double deviation = 0;
	unsigned long rounded_deviation = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (i = 0; i < GENERATE_KEY_COUNT; i++) {
		/* Make sure there is no pending i/o operation */
		sync();

		clock_gettime(CLOCK_REALTIME, &start);
		ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
					   ARRAY_SIZE(key_attrs), &hkey[i]);
		clock_gettime(CLOCK_REALTIME, &end);
		if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
			goto end;

		if (ADD_OVERFLOW(start.tv_sec * SEC_TO_MILLISEC,
				 start.tv_nsec / NS_TO_MILLISEC, &start_ms))
			goto end;

		if (ADD_OVERFLOW(end.tv_sec * SEC_TO_MILLISEC,
				 end.tv_nsec / NS_TO_MILLISEC, &end_ms))
			goto end;

		if (SUB_OVERFLOW(end_ms, start_ms, &next_run))
			goto end;

		if (ADD_OVERFLOW(average, next_run, &average))
			goto end;

		if (MUL_OVERFLOW(next_run, next_run, &next_run))
			goto end;

		deviation += next_run;
	}

	TEST_OUT("Key Destroy\n");
	for (i = 0; i < GENERATE_KEY_COUNT; i++) {
		ret = pfunc->C_DestroyObject(sess, hkey[i]);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;
	}

	average = average / GENERATE_KEY_COUNT;
	TEST_OUT("Average time %ld\n", average);
	deviation = deviation / GENERATE_KEY_COUNT - average * average;
	deviation = sqrt(deviation);
	rounded_deviation = deviation;
	TEST_OUT("Standard deviation %ld\n", rounded_deviation);

	/*
	 * Check that 68% of values are in range
	 * [average - deviation; average + deviation]
	 */
	if (rounded_deviation > average) {
		TEST_OUT("Key generation performance issue\n");
		status = TEST_FAIL;
	} else {
		status = TEST_PASS;
	}

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_performance(void *lib_hdl, CK_VOID_PTR pfunc)
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

	status = generate_cipher_key_performance(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
#else
void tests_pkcs11_performance(void *lib_hdl, CK_VOID_PTR pfunc)
{
	(void)lib_hdl;
	(void)pfunc;

	TEST_START();

	TEST_OUT("Performance test disabled in debug build\n");

	TEST_END(TEST_SKIP);
}
#endif
