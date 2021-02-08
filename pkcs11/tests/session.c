// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "local.h"

static CK_RV test_notify(CK_SESSION_HANDLE session, CK_NOTIFICATION event,
			 CK_VOID_PTR app)
{
	CK_BYTE myapp;

	if (!app)
		return CKR_ARGUMENTS_BAD;

	myapp = *(CK_BYTE_PTR)app;

	TEST_OUT("Test Notification:\n");
	TEST_OUT("\tsession: %lu\n", session);
	TEST_OUT("\tevent: %lu\n", event);
	TEST_OUT("\tapp: %u\n", myapp);
	return CKR_OK;
}

static int open_session_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_RV exp_ret;
	CK_ULONG idx;
	CK_ULONG idx_p;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_slots_present = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SLOT_ID_PTR slots_present = NULL;
	CK_SESSION_HANDLE sess;
	CK_BYTE myapp = 0;

	SUBTEST_START(status);

	TEST_OUT("Get Nb slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_FALSE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots_present);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (nb_slots_present) {
		slots_present = malloc(nb_slots_present * sizeof(CK_SLOT_ID));
		if (CHECK_EXPECTED(slots_present, "Allocation error"))
			goto end;
	}

	TEST_OUT("Check all parameters NULL\n");
	ret = pfunc->C_OpenSession(slots[0], 0, NULL, NULL, NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_OpenSession"))
		goto end;

	TEST_OUT("Check Bad Flags and No Notify/application\n");
	ret = pfunc->C_OpenSession(slots[0], 0, NULL, NULL, &sess);
	if (CHECK_CK_RV(CKR_SESSION_PARALLEL_NOT_SUPPORTED, "C_OpenSession"))
		goto end;

	TEST_OUT("Check Notify/application but bad flag\n");
	ret = pfunc->C_OpenSession(slots[0], 0, &myapp, &test_notify, &sess);
	if (CHECK_CK_RV(CKR_SESSION_PARALLEL_NOT_SUPPORTED, "C_OpenSession"))
		goto end;

	TEST_OUT("Check Application but NO Notify\n");
	ret = pfunc->C_OpenSession(slots[0], CKF_SERIAL_SESSION, &myapp, NULL,
				   &sess);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_OpenSession"))
		goto end;

	TEST_OUT("Check Notify but NO Application\n");
	ret = pfunc->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL,
				   &test_notify, &sess);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_OpenSession"))
		goto end;

	TEST_OUT("Check Open R/O Session - Bad slot ID\n");
	ret = pfunc->C_OpenSession(nb_slots, CKF_SERIAL_SESSION, NULL, NULL,
				   &sess);
	if (CHECK_CK_RV(CKR_SLOT_ID_INVALID, "C_OpenSession"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		exp_ret = CKR_TOKEN_NOT_PRESENT;

		for (idx_p = 0; idx_p < nb_slots_present; idx_p++) {
			if (slots_present[idx_p] == slots[idx]) {
				exp_ret = CKR_TOKEN_NOT_RECOGNIZED;
				break;
			}
		}

		TEST_OUT("Check Open R/O Session - no Token Init - Slot %s\n",
			 (exp_ret == CKR_TOKEN_NOT_PRESENT) ? "Not Present" :
							      "Present");
		ret = pfunc->C_OpenSession(slots[idx], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess);

		if (CHECK_CK_RV(exp_ret, "C_OpenSession"))
			goto end;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (slots_present)
		free(slots_present);

	SUBTEST_END(status);
	return status;
}

static CK_RV get_session_info(CK_FUNCTION_LIST_PTR pfunc,
			      CK_SESSION_HANDLE sess, CK_SESSION_INFO_PTR info)
{
	CK_RV ret;

	memset(info, 0, sizeof(*info));

	ret = pfunc->C_GetSessionInfo(sess, info);
	if (ret != CKR_OK)
		return ret;

	TEST_OUT("\nSession #%lu\n", sess);
	TEST_OUT("\tSlot ID  : %lu [%s]\n", info->slotID,
		 get_slot_label(info->slotID));
	TEST_OUT("\tFlags    : %lu\n", info->flags);
	TEST_OUT("\tDev Error: %lu\n", info->ulDeviceError);
	TEST_OUT("\tState    : %lu\n", info->state);

	return ret;
}

static int open_session_no_login(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[2] = { 0 };
	CK_UTF8CHAR label[32];
	CK_SESSION_INFO info;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		memset(label, ' ', sizeof(label));
		memcpy(label, exp_slots[slots[idx]].label,
		       strlen(exp_slots[slots[idx]].label));
		ret = pfunc->C_InitToken(slots[idx], NULL, 0, label);

		TEST_OUT("\n-- Check Session on Slot %lu [%s] --\n", slots[idx],
			 get_slot_label(slots[idx]));

		TEST_OUT("Check Open R/O Session\n");
		ret = pfunc->C_OpenSession(slots[idx], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/O Session #%lu\n", sess[0]);

		TEST_OUT("Check Open R/W Session\n");
		ret = pfunc->C_OpenSession(slots[idx],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[1]);

		/*
		 * Get the Sessions info
		 */
		TEST_OUT("Check R/O Session info\n");
		ret = get_session_info(pfunc, sess[0], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == CKF_SERIAL_SESSION,
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RO_PUBLIC_SESSION,
				   "Bad Session state expected %lu",
				   CKS_RO_PUBLIC_SESSION))
			goto end;

		TEST_OUT("Check R/W Session info\n");
		ret = get_session_info(pfunc, sess[1], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION |
						  CKF_RW_SESSION),
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION | CKF_RW_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RW_PUBLIC_SESSION,
				   "Bad Session state expected %lu",
				   CKS_RW_PUBLIC_SESSION))
			goto end;

		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[0] = 0;

		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[1] = 0;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess[0]) {
		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	if (sess[1]) {
		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	SUBTEST_END(status);
	return status;
}

static int open_session_so_login_fail(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[2] = { 0 };
	CK_UTF8CHAR label[32];
	CK_SESSION_INFO info;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		memset(label, ' ', sizeof(label));
		memcpy(label, exp_slots[slots[idx]].label,
		       strlen(exp_slots[slots[idx]].label));
		ret = pfunc->C_InitToken(slots[idx], NULL, 0, label);

		TEST_OUT("\n-- Check Session on Slot %lu [%s] --\n", slots[idx],
			 get_slot_label(slots[idx]));

		TEST_OUT("Check Open R/O Session\n");
		ret = pfunc->C_OpenSession(slots[idx], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/O Session #%lu\n", sess[0]);

		TEST_OUT("Check Open R/W Session\n");
		ret = pfunc->C_OpenSession(slots[idx],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[1]);

		TEST_OUT("Login to R/W Session as SO - Failure\n");
		ret = pfunc->C_Login(sess[1], CKU_SO, NULL, 0);
		if (CHECK_CK_RV(CKR_SESSION_READ_ONLY_EXISTS, "C_Login"))
			goto end;
		/*
		 * Get the Sessions info
		 */
		TEST_OUT("Check R/O Session info\n");
		ret = get_session_info(pfunc, sess[0], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == CKF_SERIAL_SESSION,
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RO_PUBLIC_SESSION,
				   "Bad Session state expected %lu",
				   CKS_RO_PUBLIC_SESSION))
			goto end;

		TEST_OUT("Check R/W Session info\n");
		ret = get_session_info(pfunc, sess[1], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION |
						  CKF_RW_SESSION),
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION | CKF_RW_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RW_PUBLIC_SESSION,
				   "Bad Session state expected %lu",
				   CKS_RW_PUBLIC_SESSION))
			goto end;

		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[0] = 0;

		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[1] = 0;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess[0]) {
		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	if (sess[1]) {
		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	SUBTEST_END(status);
	return status;
}

static int open_session_user_login(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[2] = { 0 };
	CK_UTF8CHAR label[32];
	CK_SESSION_INFO info;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		memset(label, ' ', sizeof(label));
		memcpy(label, exp_slots[slots[idx]].label,
		       strlen(exp_slots[slots[idx]].label));
		ret = pfunc->C_InitToken(slots[idx], NULL, 0, label);

		TEST_OUT("\n-- Check Session on Slot %lu [%s] --\n", slots[idx],
			 get_slot_label(slots[idx]));

		TEST_OUT("Check Open R/O Session\n");
		ret = pfunc->C_OpenSession(slots[idx], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/O Session #%lu\n", sess[0]);

		TEST_OUT("Check Open R/W Session\n");
		ret = pfunc->C_OpenSession(slots[idx],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[1]);

		TEST_OUT("Login to R/W Session as User");
		ret = pfunc->C_Login(sess[1], CKU_USER, NULL, 0);
		if (CHECK_CK_RV(CKR_OK, "C_Login"))
			goto end;
		/*
		 * Get the Sessions info
		 */
		TEST_OUT("Check R/O Session info\n");
		ret = get_session_info(pfunc, sess[0], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == CKF_SERIAL_SESSION,
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RO_USER_FUNCTIONS,
				   "Bad Session state expected %lu",
				   CKS_RO_USER_FUNCTIONS))
			goto end;

		TEST_OUT("Check R/W Session info\n");
		ret = get_session_info(pfunc, sess[1], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION |
						  CKF_RW_SESSION),
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION | CKF_RW_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RW_USER_FUNCTIONS,
				   "Bad Session state expected %lu",
				   CKS_RW_USER_FUNCTIONS))
			goto end;

		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[0] = 0;

		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[1] = 0;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess[0]) {
		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	if (sess[1]) {
		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	SUBTEST_END(status);
	return status;
}

static int open_session_rw_so_login(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[2] = { 0 };
	CK_UTF8CHAR label[32];
	CK_SESSION_INFO info;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		memset(label, ' ', sizeof(label));
		memcpy(label, exp_slots[slots[idx]].label,
		       strlen(exp_slots[slots[idx]].label));
		ret = pfunc->C_InitToken(slots[idx], NULL, 0, label);

		TEST_OUT("\n-- Check Session on Slot %lu [%s] --\n", slots[idx],
			 get_slot_label(slots[idx]));

		TEST_OUT("Check Open R/W Session\n");
		ret = pfunc->C_OpenSession(slots[idx],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[0]);

		TEST_OUT("Login as SO");
		ret = pfunc->C_Login(sess[0], CKU_SO, NULL, 0);
		if (CHECK_CK_RV(CKR_OK, "C_Login"))
			goto end;

		TEST_OUT("Check Open R/O Session Failure\n");
		ret = pfunc->C_OpenSession(slots[idx], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[1]);
		if (CHECK_CK_RV(CKR_SESSION_READ_WRITE_SO_EXISTS,
				"C_OpenSession"))
			goto end;

		/*
		 * Get the Sessions info
		 */
		TEST_OUT("Check R/W Session info\n");
		ret = get_session_info(pfunc, sess[0], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION |
						  CKF_RW_SESSION),
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION | CKF_RW_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RW_SO_FUNCTIONS,
				   "Bad Session state expected %lu",
				   CKS_RW_SO_FUNCTIONS))
			goto end;

		TEST_OUT("Close Session R/W #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[0] = 0;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess[0]) {
		TEST_OUT("Close Session R/W #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	if (sess[1]) {
		TEST_OUT("Close Session R/O #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	SUBTEST_END(status);
	return status;
}

static int open_session_ro_so_login(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[2] = { 0 };
	CK_UTF8CHAR label[32];
	CK_SESSION_INFO info;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		memset(label, ' ', sizeof(label));
		memcpy(label, exp_slots[slots[idx]].label,
		       strlen(exp_slots[slots[idx]].label));
		ret = pfunc->C_InitToken(slots[idx], NULL, 0, label);

		TEST_OUT("\n-- Check Session on Slot %lu [%s] --\n", slots[idx],
			 get_slot_label(slots[idx]));

		TEST_OUT("Check Open R/W Sessio\n");
		ret = pfunc->C_OpenSession(slots[idx],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[0]);

		TEST_OUT("Login as SO");
		ret = pfunc->C_Login(sess[0], CKU_SO, NULL, 0);
		if (CHECK_CK_RV(CKR_OK, "C_Login"))
			goto end;

		TEST_OUT("Check Open R/O Session Failure\n");
		ret = pfunc->C_OpenSession(slots[idx], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[1]);
		if (CHECK_CK_RV(CKR_SESSION_READ_WRITE_SO_EXISTS,
				"C_OpenSession"))
			goto end;

		/*
		 * Get the Sessions info
		 */
		TEST_OUT("Check R/W Session info\n");
		ret = get_session_info(pfunc, sess[0], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION |
						  CKF_RW_SESSION),
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION | CKF_RW_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RW_SO_FUNCTIONS,
				   "Bad Session state expected %lu",
				   CKS_RW_SO_FUNCTIONS))
			goto end;

		TEST_OUT("Close Session R/W #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[0] = 0;

		TEST_OUT("Check Open R/O Session\n");
		ret = pfunc->C_OpenSession(slots[idx], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/O Session #%lu\n", sess[0]);

		TEST_OUT("Check Open R/W Session\n");
		ret = pfunc->C_OpenSession(slots[idx],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[1]);

		/*
		 * Get the Sessions info
		 */
		TEST_OUT("Check R/O Session info\n");
		ret = get_session_info(pfunc, sess[0], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == CKF_SERIAL_SESSION,
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RO_PUBLIC_SESSION,
				   "Bad Session state expected %lu",
				   CKS_RO_PUBLIC_SESSION))
			goto end;

		TEST_OUT("Check R/W Session info\n");
		ret = get_session_info(pfunc, sess[1], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
			goto end;
		if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION |
						  CKF_RW_SESSION),
				   "Bad Session flags expected %lu",
				   CKF_SERIAL_SESSION | CKF_RW_SESSION))
			goto end;
		if (CHECK_EXPECTED(info.state == CKS_RW_SO_FUNCTIONS,
				   "Bad Session state expected %lu",
				   CKS_RW_SO_FUNCTIONS))
			goto end;

		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[0] = 0;

		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			goto end;
		sess[1] = 0;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess[0]) {
		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	if (sess[1]) {
		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	SUBTEST_END(status);
	return status;
}

static int open_session_login_test(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[2] = { 0 };
	CK_UTF8CHAR label[32];
	CK_SESSION_INFO info;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	memset(label, ' ', sizeof(label));
	memcpy(label, exp_slots[slots[0]].label,
	       strlen(exp_slots[slots[0]].label));
	ret = pfunc->C_InitToken(slots[0], NULL, 0, label);

	TEST_OUT("\n-- Check Session on Slot %lu [%s] --\n", slots[0],
		 get_slot_label(slots[0]));

	TEST_OUT("Check Open R/W Session\n");
	ret = pfunc->C_OpenSession(slots[0],
				   CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
				   NULL, &sess[0]);
	if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
		goto end;
	TEST_OUT("Opened R/W Session #%lu\n", sess[0]);

	TEST_OUT("Login as SO");
	ret = pfunc->C_Login(sess[0], CKU_SO, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/*
	 * Get the Sessions info
	 */
	TEST_OUT("Check R/W Session info\n");
	ret = get_session_info(pfunc, sess[0], &info);
	if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
		goto end;
	if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION | CKF_RW_SESSION),
			   "Bad Session flags expected %lu",
			   CKF_SERIAL_SESSION | CKF_RW_SESSION))
		goto end;
	if (CHECK_EXPECTED(info.state == CKS_RW_SO_FUNCTIONS,
			   "Bad Session state expected %lu",
			   CKS_RW_SO_FUNCTIONS))
		goto end;

	TEST_OUT("Login again as SO without logout");
	ret = pfunc->C_Login(sess[0], CKU_SO, NULL, 0);
	if (CHECK_CK_RV(CKR_USER_ALREADY_LOGGED_IN, "C_Login"))
		goto end;

	TEST_OUT("Login as User without logout SO");
	ret = pfunc->C_Login(sess[0], CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "C_Login"))
		goto end;

	TEST_OUT("Logout SO");
	ret = pfunc->C_Logout(sess[0]);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		goto end;

	/*
	 * Get the Sessions info
	 */
	TEST_OUT("Check R/W Session info\n");
	ret = get_session_info(pfunc, sess[0], &info);
	if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
		goto end;
	if (CHECK_EXPECTED(info.flags == (CKF_SERIAL_SESSION | CKF_RW_SESSION),
			   "Bad Session flags expected %lu",
			   CKF_SERIAL_SESSION | CKF_RW_SESSION))
		goto end;
	if (CHECK_EXPECTED(info.state == CKS_RW_PUBLIC_SESSION,
			   "Bad Session state expected %lu",
			   CKS_RW_PUBLIC_SESSION))
		goto end;

	TEST_OUT("Check Open R/O Session\n");
	ret = pfunc->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL,
				   &sess[1]);
	if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
		goto end;
	TEST_OUT("Opened R/O Session #%lu\n", sess[1]);

	/*
	 * Get the Sessions info
	 */
	TEST_OUT("Check R/O Session info\n");
	ret = get_session_info(pfunc, sess[1], &info);
	if (CHECK_CK_RV(CKR_OK, "C_GetSessionInfo"))
		goto end;
	if (CHECK_EXPECTED(info.flags == CKF_SERIAL_SESSION,
			   "Bad Session flags expected %lu",
			   CKF_SERIAL_SESSION))
		goto end;
	if (CHECK_EXPECTED(info.state == CKS_RO_PUBLIC_SESSION,
			   "Bad Session state expected %lu",
			   CKS_RO_PUBLIC_SESSION))
		goto end;

	TEST_OUT("Close Session R/W #%lu\n", sess[1]);
	ret = pfunc->C_CloseSession(sess[1]);
	if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
		goto end;
	sess[1] = 0;

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess[0]) {
		TEST_OUT("Close Session R/O #%lu\n", sess[0]);
		ret = pfunc->C_CloseSession(sess[0]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	if (sess[1]) {
		TEST_OUT("Close Session R/W #%lu\n", sess[1]);
		ret = pfunc->C_CloseSession(sess[1]);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	SUBTEST_END(status);
	return status;
}

static int open_session_closeall(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	unsigned int idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[10] = { 0 };
	CK_UTF8CHAR label[32];

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	memset(label, ' ', sizeof(label));
	memcpy(label, exp_slots[slots[0]].label,
	       strlen(exp_slots[slots[0]].label));
	ret = pfunc->C_InitToken(slots[0], NULL, 0, label);

	for (idx = 0; idx < ARRAY_SIZE(sess) / 2; idx++) {
		TEST_OUT("Check Open R/W Session - Slot %lu [%s]\n", slots[0],
			 get_slot_label(slots[0]));
		ret = pfunc->C_OpenSession(slots[0],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[idx]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[idx]);
	}

	for (; idx < ARRAY_SIZE(sess); idx++) {
		TEST_OUT("Check Open R/O Session - Slot %lu [%s]\n", slots[0],
			 get_slot_label(slots[0]));
		ret = pfunc->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[idx]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/O Session #%lu\n", sess[idx]);
	}

	TEST_OUT("Check Close All Sessions - Slot %lu [%s]\n", slots[0],
		 get_slot_label(slots[0]));
	ret = pfunc->C_CloseAllSessions(slots[0]);
	if (!CHECK_CK_RV(CKR_OK, "C_CloseAllSessions"))
		status = TEST_PASS;
end:
	if (slots)
		free(slots);

	SUBTEST_END(status);
	return status;
}

static int open_session_without_closure(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	unsigned int idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess[10] = { 0 };
	CK_UTF8CHAR label[32];

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (CHECK_EXPECTED(nb_slots, "Not slot present"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	TEST_OUT("\nGet slots present list\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	memset(label, ' ', sizeof(label));
	memcpy(label, exp_slots[slots[0]].label,
	       strlen(exp_slots[slots[0]].label));
	ret = pfunc->C_InitToken(slots[0], NULL, 0, label);

	for (idx = 0; idx < ARRAY_SIZE(sess) / 2; idx++) {
		TEST_OUT("Check Open R/W Session -Slot %lu [%s]\n", slots[0],
			 get_slot_label(slots[0]));
		ret = pfunc->C_OpenSession(slots[0],
					   CKF_SERIAL_SESSION | CKF_RW_SESSION,
					   NULL, NULL, &sess[idx]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/W Session #%lu\n", sess[idx]);
	}

	for (; idx < ARRAY_SIZE(sess); idx++) {
		TEST_OUT("Check Open R/O Session - Slot %lu [%s]\n", slots[0],
			 get_slot_label(slots[0]));
		ret = pfunc->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL,
					   NULL, &sess[idx]);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			goto end;
		TEST_OUT("Opened R/O Session #%lu\n", sess[idx]);
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_session(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;
	CK_RV ret;

	TEST_START(status);

	ret = pfunc->C_Initialize(NULL);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (open_session_bad_param(pfunc) == TEST_FAIL)
		goto end;

	if (open_session_no_login(pfunc) == TEST_FAIL)
		goto end;

	if (open_session_so_login_fail(pfunc) == TEST_FAIL)
		goto end;

	if (open_session_user_login(pfunc) == TEST_FAIL)
		goto end;

	if (open_session_rw_so_login(pfunc) == TEST_FAIL)
		goto end;

	if (open_session_ro_so_login(pfunc) == TEST_FAIL)
		goto end;

	if (open_session_login_test(pfunc) == TEST_FAIL)
		goto end;

	if (open_session_closeall(pfunc) == TEST_FAIL)
		goto end;

	/*
	 * This test must be the last on to force the C_Finalize
	 * operation to close all sessions.
	 */
	status = open_session_without_closure(pfunc);

end:
	ret = pfunc->C_Finalize(NULL);

	TEST_END(status);
}
