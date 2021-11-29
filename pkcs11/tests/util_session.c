// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util_session.h"

static struct tee_info {
	char ta_uuid[37];
} tee_default_info = { { "218c6053-294e-4e96-830c-e6eba4aa4345" } };

static struct se_info {
	unsigned int storage_id;
	unsigned int storage_nonce;
	unsigned short storage_replay;
} se_default_info = { 0x504b3131, 0x444546, 1000 }; // PK11, DEF

static CK_RV create_tee_info(CK_SESSION_HANDLE_PTR sess,
			     CK_FUNCTION_LIST_PTR pfunc)
{
	CK_RV ret;
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BBOOL token = true;
	CK_UTF8CHAR label[] = "TEE Info";

	CK_ATTRIBUTE data_template[] = {
		{ CKA_CLASS, &data_class, sizeof(data_class) },
		{ CKA_LABEL, &label, sizeof(label) - 1 },
		{ CKA_VALUE, &tee_default_info, sizeof(struct tee_info) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	TEST_OUT("Create %sTEE Info (UUID=%s) data object\n",
		 token ? "Token " : "", tee_default_info.ta_uuid);

	ret = pfunc->C_CreateObject(*sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (!CHECK_EXPECTED(ret == CKR_OK || ret == CKR_FUNCTION_FAILED,
			    "C_CreateObject returned 0x%lx", ret)) {
		TEST_OUT("TEE Info created #%lu\n", hdata);
		ret = CKR_OK;
	}

	return ret;
}

static CK_RV create_hsm_info(CK_SESSION_HANDLE_PTR sess,
			     CK_FUNCTION_LIST_PTR pfunc)
{
	CK_RV ret;
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BBOOL token = true;
	CK_UTF8CHAR label[] = "HSM Info";

	CK_ATTRIBUTE data_template[] = {
		{ CKA_CLASS, &data_class, sizeof(data_class) },
		{ CKA_LABEL, &label, sizeof(label) - 1 },
		{ CKA_VALUE, &se_default_info, sizeof(struct se_info) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	TEST_OUT("Create %sHSM Info (Storage ID=0x%x) data object\n",
		 token ? "Token " : "", se_default_info.storage_id);

	ret = pfunc->C_CreateObject(*sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (!CHECK_EXPECTED(ret == CKR_OK || ret == CKR_FUNCTION_FAILED,
			    "C_CreateObject returned 0x%lx", ret)) {
		TEST_OUT("HSM Info created #%lu\n", hdata);
		ret = CKR_OK;
	}

	return ret;
}

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

	TEST_OUT("Create TEE and HSM Data objects\n");
	ret = create_tee_info(sess, pfunc);
	if (CHECK_CK_RV(CKR_OK, "create_tee_info"))
		goto end;

	ret = create_hsm_info(sess, pfunc);
	if (CHECK_CK_RV(CKR_OK, "create_hsm_info"))
		goto end;

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
