// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_session.h"

struct asn1_ec_curve {
	size_t security_size;
	const char *name;
	const unsigned char *oid;
};

#define EC_STR_PRIME192_V1 "prime192v1"
#define EC_STR_PRIME256_V1 "prime256v1"

static struct asn1_ec_curve ec_curves[] = {
	{ 192, EC_STR_PRIME192_V1, prime192v1 },
	{ 256, EC_STR_PRIME256_V1, prime256v1 },
};

static int object_ec_key_public(CK_FUNCTION_LIST_PTR pfunc, CK_BBOOL token)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE pubkey[65] = {};

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_EC_POINT, &pubkey, sizeof(pubkey) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04; /* Uncompress point */
	/* Set the CKA_EC_POINT size function of the security size */
	keyTemplate[3].ulValueLen =
		BITS_TO_BYTES(ec_curves[0].security_size) * 2 + 1;

	TEST_OUT("Create %sKey Public by curve name\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_string(&keyTemplate[2],
					       ec_curves[0].name),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key public by curve name created #%lu\n", hkey);

	TEST_OUT("Create %sKey Public by curve oid\n", token ? "Token " : "");
	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2], ec_curves[0].oid),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key public created by curve oid #%lu\n", hkey);

	TEST_OUT("Key Destroy #%lu\n", hkey);
	ret = pfunc->C_DestroyObject(sess, hkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	SUBTEST_END(status);
	return status;
}

static int object_ec_key_private(CK_FUNCTION_LIST_PTR pfunc, CK_BBOOL token)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE privkey[32] = {};
	CK_BYTE pubkey[65] = {};

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_VALUE, &privkey, sizeof(privkey) },
		{ CKA_EC_POINT, &pubkey, sizeof(pubkey) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create %sKey Private by curve name\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_string(&keyTemplate[2],
					       ec_curves[0].name),
			   "ASN1 Conversion"))
		goto end;

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04; /* Uncompress point */

	/* Set the CKA_EC_POINT size function of the security size */
	keyTemplate[4].ulValueLen = BITS_TO_BYTES(192) * 2 + 1;

	/* Set the CKA_VALUE size function of the security size */
	keyTemplate[3].ulValueLen = BITS_TO_BYTES(ec_curves[0].security_size);
	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key private by curve name created #%lu\n", hkey);

	TEST_OUT("Create %sKey Private by curve oid\n", token ? "Token " : "");
	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2], ec_curves[0].oid),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key private created by curve oid #%lu\n", hkey);

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	SUBTEST_END(status);
	return status;
}

static int object_generate_ec_keypair(CK_FUNCTION_LIST_PTR pfunc,
				      CK_BBOOL token)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hpubkey;
	CK_OBJECT_HANDLE hprivkey;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };

	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
	};
	CK_ATTRIBUTE *privkey_attrs = NULL;
	CK_ULONG nb_privkey_attrs = 0;
	CK_ATTRIBUTE privkey_token[] = {
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	SUBTEST_START(status);

	if (token) {
		privkey_attrs = privkey_token;
		nb_privkey_attrs = ARRAY_SIZE(privkey_token);
	}

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate %sKeypair by curve name\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       ec_curves[0].name),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       nb_privkey_attrs, &hpubkey, &hprivkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Keypair generated by curve name pub=#%lu priv=#%lu\n",
		 hpubkey, hprivkey);

	TEST_OUT("Generate %sKeypair by curve oid\n", token ? "Token " : "");
	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	if (CHECK_EXPECTED(util_to_asn1_oid(&pubkey_attrs[0], ec_curves[0].oid),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       nb_privkey_attrs, &hpubkey, &hprivkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Keypair generated by curve oid pub=#%lu priv=#%lu\n", hpubkey,
		 hprivkey);

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_object_key_ec(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
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

	if (object_ec_key_public(pfunc, false) == TEST_FAIL)
		goto end;

	if (object_ec_key_private(pfunc, false) == TEST_FAIL)
		goto end;

	if (object_generate_ec_keypair(pfunc, false) == TEST_FAIL)
		goto end;

	if (object_ec_key_public(pfunc, true) == TEST_FAIL)
		goto end;

	if (object_ec_key_private(pfunc, true) == TEST_FAIL)
		goto end;

	status = object_generate_ec_keypair(pfunc, true);

end:
	ret = pfunc->C_Finalize(NULL);

	TEST_END(status);
}
