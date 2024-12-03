// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "os_mutex.h"
#include "local.h"
#include "util.h"

struct smw_mech_def {
	CK_MECHANISM_TYPE type;
	CK_BBOOL optional;
	CK_BBOOL found;
};

#define M(id)                                                                  \
	{                                                                      \
		.type = CKM_##id, .optional = CK_FALSE, .found = CK_FALSE      \
	}
#define M_OPT(id)                                                              \
	{                                                                      \
		.type = CKM_##id, .optional = CK_TRUE, .found = CK_FALSE       \
	}

static struct smw_mech_def mlist[] = {
	M(SHA224),
	M(SHA256),
	M(SHA384),
	M(SHA512),
	M(EC_KEY_PAIR_GEN),
	M(AES_KEY_GEN),
	M_OPT(GENERIC_SECRET_KEY_GEN),
	M(ECDSA),
	M(ECDSA_SHA1),
	M(ECDSA_SHA224),
	M(ECDSA_SHA256),
	M(ECDSA_SHA384),
	M(ECDSA_SHA512),
	M(AES_CBC),
	M(AES_ECB),
	M(AES_CCM),
	M(AES_CMAC),
	M(DES3_CMAC),
	M_OPT(SHA224_HMAC),
	M_OPT(SHA256_HMAC),
	M_OPT(SHA384_HMAC),
	M_OPT(SHA512_HMAC),
	M_OPT(SHA224_HMAC_GENERAL),
	M_OPT(SHA256_HMAC_GENERAL),
	M_OPT(SHA384_HMAC_GENERAL),
	M_OPT(SHA512_HMAC_GENERAL),
};

/*
 * Array must list mechanisms supported only by SMW TEE subsystem.
 */
static struct smw_mech_def mlist_tee[] = {
	M(MD5),
	M(SHA_1),
	M(SHA3_224),
	M(SHA3_256),
	M(SHA3_384),
	M(SHA3_512),
	M(AES_CTS),
	M(AES_CTR),
	M(DES_KEY_GEN),
	M(DES3_KEY_GEN),
	M(SM4_KEY_GEN),
	M(AES_GCM),
	M(AES_XTS),
	M(DES_CBC),
	M(DES_ECB),
	M(DES3_CBC),
	M(DES3_ECB),
	M(SM4_CBC),
	M(SM4_CTR),
	M(SM4_ECB),
	M(HKDF_DERIVE),
	M(RSA_PKCS_KEY_PAIR_GEN),
	M(RSA_PKCS),
	M(SHA1_RSA_PKCS),
	M(SHA224_RSA_PKCS),
	M(SHA256_RSA_PKCS),
	M(SHA384_RSA_PKCS),
	M(SHA512_RSA_PKCS),
	M(RSA_PKCS_PSS),
	M(SHA1_RSA_PKCS_PSS),
	M(SHA224_RSA_PKCS_PSS),
	M(SHA256_RSA_PKCS_PSS),
	M(SHA384_RSA_PKCS_PSS),
	M(SHA512_RSA_PKCS_PSS),
	M(AES_CMAC_GENERAL),
	M(DES3_CMAC_GENERAL),
	M(SHA3_224_HMAC),
	M(SHA3_256_HMAC),
	M(SHA3_384_HMAC),
	M(SHA3_512_HMAC),
	M(MD5_HMAC_GENERAL),
	M(SHA_1_HMAC_GENERAL),
	M(MD5_HMAC),
	M(SHA_1_HMAC),
	M(SHA3_224_HMAC_GENERAL),
	M(SHA3_256_HMAC_GENERAL),
	M(SHA3_384_HMAC_GENERAL),
	M(SHA3_512_HMAC_GENERAL),
};

/*
 * Array must list mechanisms supported only by SMW ELE subsystem but i.MX8ULP.
 */
static struct smw_mech_def mlist_ele[] = {
	M(MD5),
	M(SHA_1),
	M(SHA3_224),
	M(SHA3_256),
	M(SHA3_384),
	M(SHA3_512),
	M(AES_CTR),
	M(AES_GCM),
	M_OPT(CHACHA20_POLY1305),
	M(HKDF_DERIVE),
	M(RSA_PKCS_KEY_PAIR_GEN),
	M(RSA_PKCS),
	M(SHA1_RSA_PKCS),
	M(SHA224_RSA_PKCS),
	M(SHA256_RSA_PKCS),
	M(SHA384_RSA_PKCS),
	M(SHA512_RSA_PKCS),
	M(RSA_PKCS_PSS),
	M(SHA1_RSA_PKCS_PSS),
	M(SHA224_RSA_PKCS_PSS),
	M(SHA256_RSA_PKCS_PSS),
	M(SHA384_RSA_PKCS_PSS),
	M(SHA512_RSA_PKCS_PSS),
	M(AES_CMAC_GENERAL),
	M(DES3_CMAC_GENERAL),
	M(SHA3_224_HMAC),
	M(SHA3_256_HMAC),
	M(SHA3_384_HMAC),
	M(SHA3_512_HMAC),
	M(MD5_HMAC_GENERAL),
	M(SHA_1_HMAC_GENERAL),
	M(MD5_HMAC),
	M(SHA_1_HMAC),
	M(SHA3_224_HMAC_GENERAL),
	M(SHA3_256_HMAC_GENERAL),
	M(SHA3_384_HMAC_GENERAL),
	M(SHA3_512_HMAC_GENERAL),
};

/*
 * Array must list mechanisms supported only by SMW ELE subsystem i.MX8ULP.
 */
static struct smw_mech_def mlist_ele_8ulp[] = {
	M(AES_CTR),
	M(AES_CMAC_GENERAL),
	M(DES3_CMAC_GENERAL),
};

/*
 * Array must list mechanisms supported only by SMW SECO subsystem.
 */
static struct smw_mech_def mlist_seco[] = {
	M(SHA_1),
	M(AES_GCM),
};

/*
 * Keep this list in the same order as the list generated from dev_config.c.in
 * Currently, that order is: smw, ele, optee, seco; first is always smw, the rest
 * are in lexicographic order, as they are added with file(GLOB ...)
 */
const struct test_slots exp_slots[] = { {
						.num = 0,
						.label = "SMW",
						.flags_slot = 0,
					},
					{
						.num = 1,
						.label = "ELE",
						.flags_slot = CKF_HW_SLOT,
					},
					{
						.num = 2,
						.label = "OPTEE",
						.flags_slot = 0,
					},
					{
						.num = 3,
						.label = "SECO",
						.flags_slot = CKF_HW_SLOT,
					} };

#ifdef SMW_DEVICE_ONLY
#define NB_EXP_DEVICES ((size_t)1)
#else
#define NB_EXP_DEVICES ARRAY_SIZE(exp_slots)
#endif

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
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_ULONG idx = 0;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL_PTR;

	SUBTEST_START();

	TEST_OUT("Check all parameters NULL\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;
	if (CHECK_EXPECTED(nb_slots == NB_EXP_DEVICES,
			   "Got %lu but expected %zu slots", nb_slots,
			   NB_EXP_DEVICES))
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
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_ULONG idx = 0;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL_PTR;

	SUBTEST_START();

	TEST_OUT("Check all parameters NULL\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL_PTR, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
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
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_ULONG idx = 0;
	CK_ULONG idx_p = 0;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_slots_present = 0;
	CK_SLOT_ID_PTR slots = NULL_PTR;
	CK_SLOT_ID_PTR slots_present = NULL_PTR;
	CK_SLOT_INFO info = { 0 };
	CK_FLAGS exp_flags = 0;

	SUBTEST_START();

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Slot Info NULL\n");
	ret = pfunc->C_GetSlotInfo(0, NULL_PTR);
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
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL_PTR, &nb_slots_present);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (nb_slots_present) {
		slots_present = malloc(nb_slots_present * sizeof(CK_SLOT_ID));
		if (CHECK_EXPECTED(slots_present, "Allocation error"))
			goto end;

		ret = pfunc->C_GetSlotList(CK_TRUE, slots_present,
					   &nb_slots_present);
		if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
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
				   "Flags Got=0x%lX Expected=0x%lX", info.flags,
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
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_slots_present = 0;
	CK_ULONG idx = 0;
	CK_ULONG idx_p = 0;
	CK_SLOT_ID_PTR slots = NULL_PTR;
	CK_SLOT_ID_PTR slots_present = NULL_PTR;
	CK_UTF8CHAR label[32] = { 0 };
	bool slot_present = false;

	SUBTEST_START();

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_FALSE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;
	if (CHECK_EXPECTED(nb_slots == NB_EXP_DEVICES,
			   "Got %lu but expected %zu slots", nb_slots,
			   NB_EXP_DEVICES))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, NULL_PTR, &nb_slots_present);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	if (nb_slots_present) {
		slots_present = malloc(nb_slots_present * sizeof(CK_SLOT_ID));
		if (CHECK_EXPECTED(slots_present, "Allocation error"))
			goto end;

		ret = pfunc->C_GetSlotList(CK_TRUE, slots_present,
					   &nb_slots_present);
		if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
			goto end;
	}

	for (idx = 0; idx < nb_slots; idx++) {
		if (CHECK_EXPECTED(strlen(exp_slots[idx].label) <=
					   sizeof(label),
				   "Slot label overflow"))
			goto end;

		memset(label, ' ', sizeof(label));
		memcpy(label, exp_slots[idx].label,
		       strlen(exp_slots[idx].label));
		ret = pfunc->C_InitToken(idx, NULL_PTR, 0, label);

		slot_present = false;
		for (idx_p = 0; idx_p < nb_slots_present; idx_p++) {
			if (slots_present[idx_p] == slots[idx]) {
				slot_present = true;
				break;
			}
		}

		if (CHECK_CK_RV(slot_present ? CKR_OK : CKR_TOKEN_NOT_PRESENT,
				"C_InitToken"))
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

static int get_tokeninfo(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_ULONG idx = 0;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL_PTR;
	CK_TOKEN_INFO info = { 0 };
	int retcmp = 0;

	SUBTEST_START();

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Token Info NULL\n");
	ret = pfunc->C_GetTokenInfo(0, NULL_PTR);
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
			TEST_OUT("\tPublic Memory Total=N/A ");
		else
			TEST_OUT("\tPublic Memory Total=%lu ",
				 info.ulTotalPublicMemory);

		if (info.ulFreePublicMemory == CK_UNAVAILABLE_INFORMATION)
			TEST_OUT("Free=N/A\n");
		else
			TEST_OUT("Free=%lu\n", info.ulFreePublicMemory);

		if (info.ulTotalPrivateMemory == CK_UNAVAILABLE_INFORMATION)
			TEST_OUT("\tPrivate Memory Total=N/A ");
		else
			TEST_OUT("\tPrivate Memory Total=%lu ",
				 info.ulTotalPrivateMemory);

		if (info.ulFreePrivateMemory == CK_UNAVAILABLE_INFORMATION)
			TEST_OUT("Free=N/A\n");
		else
			TEST_OUT("Free=%lu\n", info.ulFreePrivateMemory);

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

static CK_BBOOL find_and_set_mechanisms(struct smw_mech_def *list,
					size_t nb_elem, CK_MECHANISM_TYPE mech)
{
	CK_BBOOL found = CK_FALSE;
	CK_ULONG idx = 0;

	for (; idx < nb_elem; idx++) {
		if (mech == list[idx].type) {
			list[idx].found = CK_TRUE;
			found = CK_TRUE;
			break;
		}
	}

	return found;
}

static CK_BBOOL check_missing_mechanisms(struct smw_mech_def *list,
					 const char *name, size_t nb_elem)
{
	CK_BBOOL missing = CK_FALSE;
	CK_ULONG idx = 0;

	for (; idx < nb_elem; idx++) {
		if (!list[idx].found) {
			TEST_OUT("%sMech #%lu of %s list (0x%lx) not found\n",
				 (list[idx].optional) ? "Optional " : "", idx,
				 name, list[idx].type);
			if (!list[idx].optional)
				missing = CK_TRUE;
		}
	}

	return missing;
}

static int get_mechanisms(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_ULONG idx = 0;
	CK_ULONG idx_m = 0;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_mechs = 0;
	CK_ULONG nb_mechs_exp = ARRAY_SIZE(mlist);
	CK_ULONG err_mechs = 0;
	CK_SLOT_ID_PTR slots = NULL_PTR;
	CK_MECHANISM_TYPE_PTR mechs = NULL_PTR;
	CK_BBOOL fmech = CK_FALSE;

	SUBTEST_START();

	if (is_tee_subsystem())
		nb_mechs_exp += ARRAY_SIZE(mlist_tee);

	if (is_ele_subsystem() && !is_8ulp())
		nb_mechs_exp += ARRAY_SIZE(mlist_ele);

	if (is_ele_subsystem() && is_8ulp())
		nb_mechs_exp += ARRAY_SIZE(mlist_ele_8ulp);

	if (is_seco_subsystem())
		nb_mechs_exp += ARRAY_SIZE(mlist_seco);

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Mechanism Bad Slot ID\n");
	ret = pfunc->C_GetMechanismList(nb_slots, NULL_PTR, &nb_mechs);
	if (CHECK_CK_RV(CKR_SLOT_ID_INVALID, "C_GetMechanisms"))
		goto end;

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		ret = pfunc->C_GetMechanismList(slots[idx], NULL_PTR,
						&nb_mechs);
		if (CHECK_CK_RV(CKR_OK, "C_GetMechanisms"))
			goto end;

		if (CHECK_EXPECTED(nb_mechs <= nb_mechs_exp,
				   "Slot [%s] Got %lu Expected %lu Mechanism",
				   get_slot_label(slots[idx]), nb_mechs,
				   ARRAY_SIZE(mlist)))
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
			if (find_and_set_mechanisms(mlist, ARRAY_SIZE(mlist),
						    mechs[idx_m]))
				continue;

			if (is_tee_subsystem() &&
			    find_and_set_mechanisms(mlist_tee,
						    ARRAY_SIZE(mlist_tee),
						    mechs[idx_m]))
				fmech = CK_TRUE;

			if (is_ele_subsystem() && !is_8ulp() &&
			    find_and_set_mechanisms(mlist_ele,
						    ARRAY_SIZE(mlist_ele),
						    mechs[idx_m]))
				fmech = CK_TRUE;

			if (is_ele_subsystem() && is_8ulp() &&
			    find_and_set_mechanisms(mlist_ele_8ulp,
						    ARRAY_SIZE(mlist_ele_8ulp),
						    mechs[idx_m]))
				fmech = CK_TRUE;

			if (is_seco_subsystem() &&
			    find_and_set_mechanisms(mlist_seco,
						    ARRAY_SIZE(mlist_seco),
						    mechs[idx_m]))
				fmech = CK_TRUE;

			if (fmech)
				continue;

			TEST_OUT("Found extra mech (0x%lx) not in list!\n",
				 mechs[idx_m]);
			goto end;
		}

		/* Parse all mechanism lists to check the missing ones */
		if (check_missing_mechanisms(mlist, "mlist", ARRAY_SIZE(mlist)))
			err_mechs++;

		if (is_tee_subsystem() &&
		    check_missing_mechanisms(mlist_tee, "mlist_tee",
					     ARRAY_SIZE(mlist_tee)))
			err_mechs++;

		if (is_ele_subsystem() && !is_8ulp() &&
		    check_missing_mechanisms(mlist_ele, "mlist_ele",
					     ARRAY_SIZE(mlist_ele)))
			err_mechs++;

		if (is_ele_subsystem() && is_8ulp() &&
		    check_missing_mechanisms(mlist_ele_8ulp, "mlist_ele_8ulp",
					     ARRAY_SIZE(mlist_ele_8ulp)))
			err_mechs++;

		if (is_seco_subsystem() &&
		    check_missing_mechanisms(mlist_seco, "mlist_seco",
					     ARRAY_SIZE(mlist_seco)))
			err_mechs++;
	}

	if (!err_mechs)
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
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_ULONG idx = 0;
	CK_ULONG idx_m = 0;
	CK_ULONG nb_slots = 0;
	CK_ULONG nb_mechs = 0;
	CK_SLOT_ID_PTR slots = NULL_PTR;
	CK_MECHANISM_TYPE_PTR mechs = NULL_PTR;
	CK_MECHANISM_INFO info = { 0 };

	SUBTEST_START();

	TEST_OUT("\nGet number of slots\n");
	ret = pfunc->C_GetSlotList(CK_FALSE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	TEST_OUT("\nGet Mechanism Info NULL\n");
	ret = pfunc->C_GetMechanismInfo(0, mlist[0].type, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetMechanismInfo"))
		goto end;

	TEST_OUT("\nGet Mechanism Info Bad Slot ID\n");
	ret = pfunc->C_GetMechanismInfo(nb_slots, mlist[0].type, &info);
	if (CHECK_CK_RV(CKR_SLOT_ID_INVALID, "C_GetMechanismInfo"))
		goto end;

	TEST_OUT("\nGet number of slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL_PTR, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	for (idx = 0; idx < nb_slots; idx++) {
		ret = pfunc->C_GetMechanismList(slots[idx], NULL_PTR,
						&nb_mechs);
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
				TEST_OUT("Slot %lu Mechanism 0x%lx info error\n",
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

void tests_pkcs11_slot_token(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (get_slotlist(pfunc) == TEST_FAIL)
		goto end;

	if (get_slotlist_present(pfunc) == TEST_FAIL)
		goto end;

	if (get_slotinfo(pfunc) == TEST_FAIL)
		goto end;

	if (get_mechanisms(pfunc) == TEST_FAIL)
		goto end;

	if (init_token(pfunc) == TEST_FAIL)
		goto end;

	if (get_tokeninfo(pfunc) == TEST_FAIL)
		goto end;

	status = get_mechanismsinfo(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
