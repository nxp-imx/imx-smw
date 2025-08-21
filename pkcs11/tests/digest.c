// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"
#include "util_digest.h"

static int digest_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM digmech = { 0 };
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	enum mechanism_id id = MECH_ID_SHA256;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	TEST_OUT("Check session NULL\n");
	digmech.mechanism = DIGEST_MECHANISM(id);
	ret = pfunc->C_DigestInit(0, &digmech);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DigestInit"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	digmech.mechanism = CKM_EC_KEY_PAIR_GEN;
	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_DigestInit"))
		goto end;

	digmech.mechanism = DIGEST_MECHANISM(id);
	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	digest_length = DIGEST_LENGTH(id);
	digest = malloc(digest_length);
	if (CHECK_EXPECTED(digest, "Allocation error"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_Digest(0, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, &digest_length);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Digest"))
		goto end;

	TEST_OUT("Check data buffer NULL\n");
	ret = pfunc->C_Digest(sess, NULL_PTR, TV_MSG_LEN(id), digest,
			      &digest_length);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Digest"))
		goto end;

	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Check data len zero\n");
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), 0, digest,
			      &digest_length);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Digest"))
		goto end;

	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Check digest len NULL\n");
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Digest"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_no_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	enum mechanism_id id = MECH_ID_SHA256;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	digest_length = DIGEST_LENGTH(id);
	digest = malloc(digest_length);
	if (CHECK_EXPECTED(digest, "Allocation error"))
		goto end;

	TEST_OUT("Check digest without init\n");
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, &digest_length);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Digest"))
		goto end;

	TEST_OUT("Check data len zero\n");
	ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DigestFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_multiple_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM digmech = { 0 };
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	enum mechanism_id id = MECH_ID_SHA256;
	bool match;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	TEST_OUT("Check mechanism NULL\n");
	ret = pfunc->C_DigestInit(sess, NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	digmech.mechanism = DIGEST_MECHANISM(id);
	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Check multiple digest init with same mechanism\n");
	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_DigestInit"))
		goto end;

	id = MECH_ID_SHA256;
	digmech.mechanism = DIGEST_MECHANISM(id);
	TEST_OUT("Check multiple digest init with different mechanism\n");
	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_DigestInit"))
		goto end;

	TEST_OUT("Check multiple digest init with NULL mechanism\n");
	ret = pfunc->C_DigestInit(sess, NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	digmech.mechanism = DIGEST_MECHANISM(id);
	TEST_OUT("Check digest init after digest terminated\n");
	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	digest_length = DIGEST_LENGTH(id);
	digest = malloc(digest_length);
	if (CHECK_EXPECTED(digest, "Allocation error"))
		goto end;
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_Digest"))
		goto end;

	match = check_digest(TV_DIGEST(id), DIGEST_LENGTH(id), digest,
			     digest_length);
	if (CHECK_EXPECTED(match, "Digest mismatch"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_bad_digest_length(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM digmech = { 0 };
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	enum mechanism_id id = MECH_ID_SHA256;
	bool match = false;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	digmech.mechanism = DIGEST_MECHANISM(id);
	ret = pfunc->C_DigestInit(sess, &digmech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Check digest length\n");
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      NULL_PTR, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_Digest"))
		goto end;

	match = check_digest_length(DIGEST_LENGTH(id), digest_length);
	if (CHECK_EXPECTED(match, "Digest length mismatch"))
		goto end;

	digest_length = DIGEST_LENGTH(id);
	digest = malloc(digest_length * 2);
	digest_length >>= 1;
	if (CHECK_EXPECTED(digest, "Allocation error"))
		goto end;

	TEST_OUT("Check digest length too short\n");
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, &digest_length);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Digest"))
		goto end;

	match = check_digest_length(DIGEST_LENGTH(id), digest_length);
	if (CHECK_EXPECTED(match, "Digest length mismatch"))
		goto end;

	TEST_OUT("Check digest length too long\n");
	digest_length <<= 1;

	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_Digest"))
		goto end;

	match = check_digest(TV_DIGEST(id), DIGEST_LENGTH(id), digest,
			     digest_length);
	if (CHECK_EXPECTED(match, "Digest mismatch"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_all_mechanisms(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM digmech = { 0 };
	CK_BYTE_PTR message = NULL_PTR;
	CK_ULONG message_length = 0;
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	unsigned int i = 0;
	bool match = false;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	for (; i < MECH_ID_NB; i++) {
		TEST_OUT("Check digest %s\n", DIGEST_NAME(i));
		digmech.mechanism = DIGEST_MECHANISM(i);

		if (!util_lib_is_mech_supported(pfunc, 0, digmech.mechanism))
			continue;

		ret = pfunc->C_DigestInit(sess, &digmech);
		if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
			goto end;

		digest_length = DIGEST_LENGTH(i);
		digest = malloc(digest_length);
		if (CHECK_EXPECTED(digest, "Allocation error"))
			goto end;

		message = (CK_BYTE_PTR)TV_MSG(i);
		message_length = TV_MSG_LEN(i);
		ret = pfunc->C_Digest(sess, message, message_length, digest,
				      &digest_length);
		if (CHECK_CK_RV(CKR_OK, "C_Digest"))
			goto end;

		match = check_digest(TV_DIGEST(i), DIGEST_LENGTH(i), digest,
				     digest_length);

		if (CHECK_EXPECTED(match, "Digest mismatch"))
			goto end;

		free(digest);
		digest = NULL_PTR;
	}

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_digest(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (digest_bad_params(pfunc) != TEST_PASS)
		goto end;

	if (digest_no_init(pfunc) != TEST_PASS)
		goto end;

	if (digest_multiple_init(pfunc) != TEST_PASS)
		goto end;

	if (digest_bad_digest_length(pfunc) != TEST_PASS)
		goto end;

	if (digest_all_mechanisms(pfunc) != TEST_PASS)
		goto end;

	status = TEST_PASS;

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
