// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util_session.h"

static int open_session(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			CK_NOTIFY callback, CK_VOID_PTR cb_args,
			CK_FLAGS sess_flags, CK_SESSION_HANDLE_PTR sess)
{
	int status = TEST_FAIL;

	CK_RV ret;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_UTF8CHAR label[32];
	const char *slot_label = NULL;

	TEST_OUT("Get Nb slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	/* Check if requested slot is present */
	for (CK_ULONG i = 0; i < nb_slots; i++) {
		if (slots[i] == p11_slot) {
			slot_label = get_slot_label(p11_slot);
			break;
		}
	}

	if (CHECK_EXPECTED(slot_label, "Slot id %lu not present", p11_slot))
		goto end;

	memset(label, ' ', sizeof(label));
	memcpy(label, slot_label, strlen(slot_label));
	ret = pfunc->C_InitToken(p11_slot, NULL, 0, label);

	TEST_OUT("-- Process #%u Open Session on Slot %lu [%s] --\n", getpid(),
		 p11_slot, slot_label);

	TEST_OUT("Check Open Session\n");
	if (callback)
		ret = pfunc->C_OpenSession(p11_slot,
					   CKF_SERIAL_SESSION | sess_flags,
					   cb_args, callback, sess);
	else
		ret = pfunc->C_OpenSession(p11_slot,
					   CKF_SERIAL_SESSION | sess_flags,
					   NULL, NULL, sess);

	if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
		goto end;
	TEST_OUT("Opened Session #%lu\n", *sess);

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	return status;
}

int util_open_rw_session(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			 CK_SESSION_HANDLE_PTR sess)
{
	return open_session(pfunc, p11_slot, NULL, NULL, CKF_RW_SESSION, sess);
}

int util_open_ro_session(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			 CK_SESSION_HANDLE_PTR sess)
{
	return open_session(pfunc, p11_slot, NULL, NULL, CKF_RW_SESSION, sess);
}

int util_open_rw_session_cb(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			    CK_NOTIFY callback, CK_VOID_PTR cb_args,
			    CK_SESSION_HANDLE_PTR sess)
{
	return open_session(pfunc, p11_slot, callback, cb_args, CKF_RW_SESSION,
			    sess);
}

int util_open_ro_session_cb(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			    CK_NOTIFY callback, CK_VOID_PTR cb_args,
			    CK_SESSION_HANDLE_PTR sess)
{
	return open_session(pfunc, p11_slot, callback, cb_args, CKF_RW_SESSION,
			    sess);
}

void util_close_session(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE_PTR sess)
{
	CK_RV ret;

	if (!(sess && *sess))
		return;

	TEST_OUT("Close Session #%lu\n", *sess);
	ret = pfunc->C_CloseSession(*sess);
	(void)CHECK_CK_RV(ret, "C_CloseSession");
}
