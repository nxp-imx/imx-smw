// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <asn1_ec_curve.h>

#include "local.h"

/*
 * ASN1 TAGs value
 */
#define ASN1_PRINTABLE_STRING  19
#define ASN1_OBJECT_IDENTIFIER 6

struct asn1_ec_curve {
	const char *name;
	const unsigned char *oid;
};

#define EC_STR_PRIME256_V1 "prime256v1"

const CK_BYTE prime256v1[] = ASN1_OID_PRIME256;

static struct asn1_ec_curve ec_curves[] = {
	{ EC_STR_PRIME256_V1, prime256v1 },
};

static int _to_asn1_string(CK_ATTRIBUTE_PTR attr, const char *str)
{
	CK_BYTE_PTR bytes;

	attr->ulValueLen = 2 + strlen(str);
	attr->pValue = malloc(attr->ulValueLen);
	if (!attr->pValue)
		return 0;

	bytes = attr->pValue;

	bytes[0] = ASN1_PRINTABLE_STRING;
	bytes[1] = strlen(str);
	memcpy(&bytes[2], str, attr->ulValueLen - 2);

	return 1;
}

static int _to_asn1_oid(CK_ATTRIBUTE_PTR attr, const CK_BYTE *oid)
{
	CK_BYTE_PTR bytes;

	attr->ulValueLen = 2 + sizeof(oid);
	attr->pValue = malloc(attr->ulValueLen);
	if (!attr->pValue)
		return 0;

	bytes = attr->pValue;

	bytes[0] = ASN1_OBJECT_IDENTIFIER;
	bytes[1] = sizeof(oid);
	memcpy(&bytes[2], oid, attr->ulValueLen - 2);

	return 1;
}

static int object_ec_key_public(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess = 0;
	CK_UTF8CHAR label[32];
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE pubkey[65] = {};

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_EC_POINT, &pubkey, sizeof(pubkey) },
	};

	SUBTEST_START(status);

	TEST_OUT("\nGet Nb slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	memset(label, ' ', sizeof(label));
	memcpy(label, exp_slots[slots[0]].label,
	       strlen(exp_slots[slots[0]].label));
	ret = pfunc->C_InitToken(slots[0], NULL, 0, label);

	TEST_OUT("\n-- Open Session on Slot %lu [%s] --\n", slots[0],
		 get_slot_label(slots[0]));

	TEST_OUT("Check Open R/W Session\n");
	ret = pfunc->C_OpenSession(slots[0],
				   CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
				   NULL, &sess);
	if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
		goto end;
	TEST_OUT("Opened R/W Session #%lu\n", sess);

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04; /* Uncompress point */

	TEST_OUT("Create Key Public by curve name\n");
	if (CHECK_EXPECTED(_to_asn1_string(&keyTemplate[2], ec_curves[0].name),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key public by curve name created #%lu\n", hkey);

	TEST_OUT("Create Key Public by curve oid\n");
	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	if (CHECK_EXPECTED(_to_asn1_oid(&keyTemplate[2], ec_curves[0].oid),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key public created by curve oid #%lu\n", hkey);

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess) {
		TEST_OUT("Close Session R/W #%lu\n", sess);
		ret = pfunc->C_CloseSession(sess);
		if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
			status = TEST_FAIL;
	}

	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	SUBTEST_END(status);
	return status;
}

static int object_ec_key_private(CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	CK_RV ret;
	CK_ULONG nb_slots = 0;
	CK_SLOT_ID_PTR slots = NULL;
	CK_SESSION_HANDLE sess = 0;
	CK_UTF8CHAR label[32];
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE privkey[32] = {};

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_VALUE, &privkey, sizeof(privkey) },
	};

	SUBTEST_START(status);

	TEST_OUT("\nGet Nb slots present\n");
	ret = pfunc->C_GetSlotList(CK_TRUE, NULL, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	slots = malloc(nb_slots * sizeof(CK_SLOT_ID));
	if (CHECK_EXPECTED(slots, "Allocation error"))
		goto end;

	ret = pfunc->C_GetSlotList(CK_TRUE, slots, &nb_slots);
	if (CHECK_CK_RV(CKR_OK, "C_GetSlotList"))
		goto end;

	memset(label, ' ', sizeof(label));
	memcpy(label, exp_slots[slots[0]].label,
	       strlen(exp_slots[slots[0]].label));
	ret = pfunc->C_InitToken(slots[0], NULL, 0, label);

	TEST_OUT("\n-- Open Session on Slot %lu [%s] --\n", slots[0],
		 get_slot_label(slots[0]));

	TEST_OUT("Check Open R/W Session\n");
	ret = pfunc->C_OpenSession(slots[0],
				   CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
				   NULL, &sess);
	if (CHECK_CK_RV(CKR_OK, "C_OpenSession"))
		goto end;
	TEST_OUT("Opened R/W Session #%lu\n", sess);

	TEST_OUT("Login to R/W Session as User");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create Key Private by curve name\n");
	if (CHECK_EXPECTED(_to_asn1_string(&keyTemplate[2], ec_curves[0].name),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key private by curve name created #%lu\n", hkey);

	TEST_OUT("Create Key Private by curve oid\n");
	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	if (CHECK_EXPECTED(_to_asn1_oid(&keyTemplate[2], ec_curves[0].oid),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key private created by curve oid #%lu\n", hkey);

	status = TEST_PASS;
end:
	if (slots)
		free(slots);

	if (sess) {
		TEST_OUT("Close Session R/W #%lu\n", sess);
		ret = pfunc->C_CloseSession(sess);
		if (CHECK_CK_RV(CKR_OK, "C_CloseSession"))
			status = TEST_FAIL;
	}

	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_object(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	(void)lib_hdl;
	int status;

	CK_RV ret;

	TEST_START(status);

	ret = pfunc->C_Initialize(NULL);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (object_ec_key_public(pfunc) == TEST_FAIL)
		goto end;

	status = object_ec_key_private(pfunc);

end:
	ret = pfunc->C_Finalize(NULL);

	TEST_END(status);
}
