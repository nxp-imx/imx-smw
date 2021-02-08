// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "local.h"

#define M(id) CKM_##id

static CK_MECHANISM_TYPE mdigest[] = {
	M(SHA_1), M(SHA224), M(SHA256), M(SHA384), M(SHA512),
};

const struct test_slots exp_slots[] = { {
						.num = 0,
						.label = "HSM",
						.flags_slot = CKF_HW_SLOT,
					},
					{
						.num = 1,
						.label = "OPTEE",
						.flags_slot = 0,
					} };

const char *get_slot_label(CK_ULONG slotid)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(exp_slots); i++) {
		if (exp_slots[i].num == slotid)
			return exp_slots[i].label;
	}

	return NULL;
}

static int get_slotlist(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;

	SUBTEST_START(status);

	TEST_OUT("Check all parameters NULL\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;
	if (CHECK_EXPECTED(nb_slots == ARRAY_SIZE(exp_slots),
			   "Got %lu but expected %zu slots", nb_slots,
			   ARRAY_SIZE(exp_slots)))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	nb_slots--;
	TEST_OUT("\nCheck too small number (%lu vs %lu)\n", nb_slots,
		 nb_slots + 1);
	ret = pfunc->C_GetSlotList(CK_FALSE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetSlotList"))
		goto end;

	nb_slots++;
	TEST_OUT("\nGet all slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		if (CHECK_EXPECTED(exp_slots[idx].num == slots[idx],
				   "Bad %lu slot id, expected %lu", slots[idx],
				   exp_slots[idx].num))
			goto end;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	SUBTEST_END(status);
	return status;
}

static int get_slotlist_present(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;

	SUBTEST_START(status);

	TEST_OUT("Check all parameters NULL\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;
	if (CHECK_EXPECTED(nb_slots == 1,
			   "Got %lu but expected %zu slots present", nb_slots,
			   1))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	nb_slots--;
	TEST_OUT("\nCheck too small number (%lu vs %lu)\n", nb_slots,
		 nb_slots + 1);
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetSlotList"))
		goto end;

	nb_slots++;
	TEST_OUT("\nGet all slots\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		if (CHECK_EXPECTED(exp_slots[idx].num == slots[idx],
				   "Bad %lu slot id, expected %lu", slots[idx],
				   exp_slots[idx].num))
			goto end;
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	SUBTEST_END(status);
	return status;
}

static int get_slotinfo(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG idx_p;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_slots_present = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SLOT_ID_PTR slots_present = NULL;
	CK_SLOT_INFO info;
	CK_FLAGS exp_flags;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Slot Info NULL\n");
	ret = pfunc->C_GetSlotInfo(0, NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetSlotInfo"))
		goto end;

	TEST_OUT("\nGet Slot Info Bad Slot ID\n");
	ret = pfunc->C_GetSlotInfo(nb_slots, &info);
	if (CHECK_CK_RV(CKR_SLOT_ID_INVALID, "C_GetSlotInfo"))
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

	for (idx = 0; idx < nb_slots; idx++) {
		ret = pfunc->C_GetSlotInfo(slots[idx], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetSlotInfo"))
			goto end;

		TEST_OUT("\n\nSlot:\n");
		TEST_OUT("\tdescripton:   %.*s!\n",
			 (int)sizeof(info.slotDescription),
			 info.slotDescription);
		TEST_OUT("\tmanufacturer: %.*s!\n",
			 (int)sizeof(info.manufacturerID), info.manufacturerID);
		TEST_OUT("\tflags 0x%lX\n", info.flags);
		TEST_OUT("\tHW version:   %01d.%01d\n",
			 info.hardwareVersion.major,
			 info.hardwareVersion.minor);
		TEST_OUT("\tSW version:   %01d.%01d\n",
			 info.firmwareVersion.major,
			 info.firmwareVersion.minor);

		exp_flags = exp_slots[idx].flags_slot;
		for (idx_p = 0; idx_p < nb_slots_present; idx_p++) {
			if (slots_present[idx_p] == slots[idx]) {
				exp_flags |= CKF_TOKEN_PRESENT;
				break;
			}
		}

		if (CHECK_EXPECTED(info.flags == exp_flags,
				   "Flags Got=0x%X Expected=0x%X", info.flags,
				   exp_flags))
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

static int init_token(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_slots_present = 0;
	CK_ULONG idx;
	CK_ULONG idx_p;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SLOT_ID_PTR slots_present = NULL;
	CK_UTF8CHAR label[32];
	bool slot_present;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_FALSE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;
	if (CHECK_EXPECTED(nb_slots == ARRAY_SIZE(exp_slots),
			   "Got %lu but expected %zu slots", nb_slots,
			   ARRAY_SIZE(exp_slots)))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots_present);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (nb_slots_present) {
		slots_present = malloc(nb_slots_present * sizeof(CK_SLOT_ID));
		if (CHECK_EXPECTED(slots_present, "Allocation error"))
			goto end;
	}

	for (idx = 0; idx < nb_slots; idx++) {
		memset(label, ' ', sizeof(label));
		memcpy(label, exp_slots[idx].label,
		       strlen(exp_slots[idx].label));
		ret = pfunc->C_InitToken(idx, NULL, 0, label);

		slot_present = false;
		for (idx_p = 0; idx_p < nb_slots_present; idx_p++) {
			if (slots_present[idx_p] == slots[idx]) {
				slot_present = true;
				break;
			}
		}
		if (slot_present) {
			if (CHECK_CK_RV(CKR_OK, "C_InitToken"))
				goto end;
		} else {
			if (CHECK_CK_RV(CKR_TOKEN_NOT_PRESENT, "C_InitToken"))
				goto end;
		}
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

static int get_tokeninfo(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_TOKEN_INFO info;
	int retcmp;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Token Info NULL\n");
	ret = pfunc->C_GetTokenInfo(0, NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetTokenInfo"))
		goto end;

	TEST_OUT("\nGet Token Info Bad Slot ID\n");
	ret = pfunc->C_GetTokenInfo(nb_slots, &info);
	if (CHECK_CK_RV(CKR_SLOT_ID_INVALID, "C_GetTokenInfo"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_FALSE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		ret = pfunc->C_GetTokenInfo(slots[idx], &info);
		if (CHECK_CK_RV(CKR_OK, "C_GetTokenInfo"))
			goto end;

		TEST_OUT("\n\nToken [%s]:\n", get_slot_label(slots[idx]));
		TEST_OUT("\tlabel:         %.*s!\n", (int)sizeof(info.label),
			 info.label);
		TEST_OUT("\tmanufacturer:  %.*s!\n",
			 (int)sizeof(info.manufacturerID), info.manufacturerID);
		TEST_OUT("\tmodel:         %.*s!\n", (int)sizeof(info.model),
			 info.model);
		TEST_OUT("\tserial number: %.*s!\n",
			 (int)sizeof(info.serialNumber), info.serialNumber);
		TEST_OUT("\tflags 0x%lX\n", info.flags);
		if (info.ulMaxSessionCount == CK_UNAVAILABLE_INFORMATION)
			TEST_OUT("\tsession Max=N/A Opened=%lu\n",
				 info.ulSessionCount);
		else if (info.ulMaxSessionCount == CK_EFFECTIVELY_INFINITE)
			TEST_OUT("\tsession Max=Infinite Opened=%lu\n",
				 info.ulSessionCount);
		else
			TEST_OUT("\tsession Max=%lu Opened=%lu\n",
				 info.ulMaxSessionCount, info.ulSessionCount);

		if (info.ulMaxRwSessionCount == CK_UNAVAILABLE_INFORMATION)
			TEST_OUT("\tR/W session Max=N/A Opened=%lu\n",
				 info.ulRwSessionCount);
		else if (info.ulMaxRwSessionCount == CK_EFFECTIVELY_INFINITE)
			TEST_OUT("\tR/W session Max=Infinite Opened=%lu\n",
				 info.ulRwSessionCount);
		else
			TEST_OUT("\tR/W session Max=%lu Opened=%lu\n",
				 info.ulMaxRwSessionCount,
				 info.ulRwSessionCount);

		TEST_OUT("\tPin Length Max=%lu Min=%lu\n", info.ulMaxPinLen,
			 info.ulMinPinLen);

		if (info.ulTotalPublicMemory == CK_UNAVAILABLE_INFORMATION)
			TEST_OUT("\tPublic Memory Total=N/A Free=%lu\n",
				 info.ulFreePublicMemory);
		else
			TEST_OUT("\tPublic Memory Total=%lu Free=%lu\n",
				 info.ulTotalPublicMemory,
				 info.ulFreePublicMemory);

		if (info.ulTotalPrivateMemory == CK_UNAVAILABLE_INFORMATION)
			TEST_OUT("\tPrivate Memory Total=N/A Free=%lu\n",
				 info.ulFreePrivateMemory);
		else
			TEST_OUT("\tPrivate Memory Total=%lu Free=%lu\n",
				 info.ulTotalPrivateMemory,
				 info.ulFreePrivateMemory);

		TEST_OUT("\tHW version:   %01d.%01d\n",
			 info.hardwareVersion.major,
			 info.hardwareVersion.minor);
		TEST_OUT("\tSW version:   %01d.%01d\n",
			 info.firmwareVersion.major,
			 info.firmwareVersion.minor);
		TEST_OUT("\tUTC Time: %.*s!\n", (int)sizeof(info.utcTime),
			 info.utcTime);

		if (info.flags & CKF_TOKEN_INITIALIZED) {
			TEST_OUT("Token is initialized\n");
			retcmp = strncmp((const char *)info.label,
					 exp_slots[idx].label,
					 strlen(exp_slots[idx].label));
			if (CHECK_EXPECTED(retcmp == 0, "Expected Label %s",
					   exp_slots[idx].label))
				goto end;
		} else {
			TEST_OUT("Token is NOT initialized\n");
		}
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	SUBTEST_END(status);
	return status;
}

static int get_mechanisms(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG idx_m;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_mechs = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_MECHANISM_TYPE_PTR mechs = NULL;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Mechanism Bad Slot ID\n");
	ret = pfunc->C_GetMechanismList(nb_slots, NULL, &nb_mechs);
	if (CHECK_CK_RV(CKR_SLOT_ID_INVALID, "C_GetMechanisms"))
		goto end;

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		ret = pfunc->C_GetMechanismList(slots[idx], NULL, &nb_mechs);
		if (CHECK_CK_RV(CKR_OK, "C_GetMechanisms"))
			goto end;

		if (CHECK_EXPECTED(nb_mechs == ARRAY_SIZE(mdigest),
				   "Slot [%s] Got %lu Expectd %lu Mechanism",
				   get_slot_label(slots[idx]), nb_mechs,
				   ARRAY_SIZE(mdigest)))
			goto end;

		if (mechs)
			free(mechs);

		mechs = malloc(nb_mechs * sizeof(CK_MECHANISM_TYPE));
		if (CHECK_EXPECTED(mechs, "Allocation error"))
			goto end;

		ret = pfunc->C_GetMechanismList(slots[idx], mechs, &nb_mechs);
		if (CHECK_CK_RV(CKR_OK, "C_GetMechanisms"))
			goto end;

		for (idx_m = 0; idx_m < nb_mechs; idx_m++) {
			if (CHECK_EXPECTED(mechs[idx_m] == mdigest[idx_m],
					   "Mech %d Got 0x%lx Expected 0x%lx",
					   mechs[idx_m], mdigest[idx_m]))
				goto end;
		}
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (mechs)
		free(mechs);

	SUBTEST_END(status);
	return status;
}

static int get_mechanismsinfo(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG idx;
	CK_ULONG idx_m;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_mechs = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_MECHANISM_TYPE_PTR mechs = NULL;
	CK_MECHANISM_INFO info;

	SUBTEST_START(status);

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Mechanism Info NULL\n");
	ret = pfunc->C_GetMechanismInfo(0, mdigest[0], NULL);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetMechanismInfo"))
		goto end;

	TEST_OUT("\nGet Mechanism Info Bad Slot ID\n");
	ret = pfunc->C_GetMechanismInfo(nb_slots, mdigest[0], &info);
	if (CHECK_CK_RV(CKR_SLOT_ID_INVALID, "C_GetMechanismInfo"))
		goto end;

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		ret = pfunc->C_GetMechanismList(slots[idx], NULL, &nb_mechs);
		if (CHECK_CK_RV(CKR_OK, "C_GetMechanisms"))
			goto end;

		mechs = malloc(nb_mechs * sizeof(CK_MECHANISM_TYPE));
		if (CHECK_EXPECTED(mechs, "Allocation error"))
			goto end;

		ret = pfunc->C_GetMechanismList(slots[idx], mechs, &nb_mechs);
		if (CHECK_CK_RV(CKR_OK, "C_GetMechanisms"))
			goto end;

		TEST_OUT("\nMechanisms info of Slot [%s]:\n",
			 get_slot_label(slots[idx]));
		for (idx_m = 0; idx_m < nb_mechs; idx_m++) {
			ret = pfunc->C_GetMechanismInfo(slots[idx],
							mechs[idx_m], &info);
			if (CHECK_CK_RV(CKR_OK, "C_GetMechanismInfo")) {
				TEST_OUT("Slot %lu Mechanism 0x%lx info error",
					 slots[idx], mechs[idx_m]);
				goto end;
			}

			TEST_OUT("\tMechanism 0x%lx\n", mechs[idx_m]);
			TEST_OUT("\t\tKey Max=%lu Min=%lu\n", info.ulMaxKeySize,
				 info.ulMinKeySize);
			TEST_OUT("\t\tFlags=0x%lx\n", info.flags);
		}
	}

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (mechs)
		free(mechs);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_slot_token(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;

	TEST_START(status);

	ret = pfunc->C_Initialize(NULL);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (get_slotlist(pfunc) == TEST_FAIL)
		goto end;

	if (get_slotlist_present(pfunc) == TEST_FAIL)
		goto end;

	if (get_slotinfo(pfunc) == TEST_FAIL)
		goto end;

	if (init_token(pfunc) == TEST_FAIL)
		goto end;

	if (get_tokeninfo(pfunc) == TEST_FAIL)
		goto end;

	if (get_mechanisms(pfunc) == TEST_FAIL)
		goto end;

	status = get_mechanismsinfo(pfunc);

end:
	ret = pfunc->C_Finalize(NULL);

	TEST_END(status);
}
