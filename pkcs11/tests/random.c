// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"

#include "util_session.h"

static int random_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE_PTR random = NULL_PTR;
	CK_ULONG random_length = 32;

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	random = malloc(random_length);
	if (CHECK_EXPECTED(random, "Allocation error"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_GenerateRandom(0, random, random_length);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_GenerateRandom"))
		goto end;

	TEST_OUT("Check random number buffer NULL\n");
	ret = pfunc->C_GenerateRandom(sess, NULL_PTR, random_length);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GenerateRandom"))
		goto end;

	TEST_OUT("Check random number length zero\n");
	ret = pfunc->C_GenerateRandom(sess, random, 0);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GenerateRandom"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (random)
		free(random);

	SUBTEST_END(status);
	return status;
}

static int random_multiple_length(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE_PTR random = NULL_PTR;
	CK_ULONG random_length = 65535;
	bool diff;

	unsigned char *latest = NULL;

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	random = malloc(random_length);
	if (CHECK_EXPECTED(random, "Allocation error"))
		goto end;
	memset(random, 0, random_length);

	latest = malloc(random_length);
	if (CHECK_EXPECTED(latest, "Allocation error"))
		goto end;
	memset(latest, 0, random_length);

	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	random_length = 16384;
	memcpy(latest, random, random_length);
	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	random_length = 4096;
	memcpy(latest, random, random_length);
	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	random_length = 1024;
	memcpy(latest, random, random_length);
	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	random_length = 256;
	memcpy(latest, random, random_length);
	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	random_length = 64;
	memcpy(latest, random, random_length);
	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	random_length = 32;
	memcpy(latest, random, random_length);
	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	random_length = 16;
	memcpy(latest, random, random_length);
	TEST_OUT("Check random number length: %ld\n", random_length);
	ret = pfunc->C_GenerateRandom(sess, random, random_length);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateRandom"))
		goto end;
	diff = memcmp(latest, random, random_length);
	if (CHECK_EXPECTED(diff, "Random number has not changed"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (random)
		free(random);

	if (latest)
		free(latest);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_random(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
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

	if (random_bad_params(pfunc) != TEST_PASS)
		goto end;

	if (random_multiple_length(pfunc) != TEST_PASS)
		goto end;

	status = TEST_PASS;

end:
	ret = pfunc->C_Finalize(NULL_PTR);

	TEST_END(status);
}
