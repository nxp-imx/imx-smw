// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <asn1_ec_curve.h>

#include "os_mutex.h"
#include "util_session.h"

#define NB_MAX_KEY 8

static CK_ULONG nb_aes_keys;

static int create_ec_key_public(CK_FUNCTION_LIST_PTR pfunc,
				CK_SESSION_HANDLE_PTR sess, CK_BBOOL token,
				CK_OBJECT_HANDLE_PTR hkey)
{
	int status;

	CK_RV ret;
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE pubkey[65] = {};
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_EC_POINT, &pubkey, sizeof(pubkey) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START(status);

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04; /* Uncompress point */

	/* Set the CKA_EC_POINT size function of the security size */
	keyTemplate[3].ulValueLen = BITS_TO_BYTES(192) * 2 + 1;

	TEST_OUT("Create %sKey Public by curve oid\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2], prime192v1),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(*sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key public created by curve oid #%lu\n", *hkey);

	status = TEST_PASS;
end:
	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	SUBTEST_END(status);
	return status;
}

static int create_ec_key_private(CK_FUNCTION_LIST_PTR pfunc,
				 CK_SESSION_HANDLE_PTR sess, CK_BBOOL token,
				 CK_OBJECT_HANDLE_PTR hkey)
{
	int status;

	CK_RV ret;
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE privkey[32] = {};
	CK_BYTE pubkey[65] = {};
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_VALUE, &privkey, sizeof(privkey) },
		{ CKA_EC_POINT, &pubkey, sizeof(pubkey) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START(status);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create %sKey Private by curve oid\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2], prime192v1),
			   "ASN1 Conversion"))
		goto end;

	/* Set the CKA_VALUE size function of the security size */
	keyTemplate[3].ulValueLen = BITS_TO_BYTES(192);

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04; /* Uncompress point */

	/* Set the CKA_EC_POINT size function of the security size */
	keyTemplate[4].ulValueLen = BITS_TO_BYTES(192) * 2 + 1;

	ret = pfunc->C_CreateObject(*sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key private created by curve oid #%lu\n", *hkey);

	status = TEST_PASS;
end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		goto end;

	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	SUBTEST_END(status);
	return status;
}

static int generate_ec_keypair(CK_FUNCTION_LIST_PTR pfunc,
			       CK_SESSION_HANDLE_PTR sess, CK_BBOOL token,
			       CK_OBJECT_HANDLE_PTR hkeys)
{
	int status;

	CK_RV ret;
	CK_OBJECT_HANDLE hpubkey;
	CK_OBJECT_HANDLE hprivkey;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_VERIFY, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE *privkey_attrs = NULL;
	CK_ULONG nb_privkey_attrs = 0;
	CK_ATTRIBUTE privkey_token[] = {
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START(status);

	if (token) {
		privkey_attrs = privkey_token;
		nb_privkey_attrs = ARRAY_SIZE(privkey_token);
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate %sKeypair by curve oid\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_oid(&pubkey_attrs[0], prime192v1),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(*sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       nb_privkey_attrs, &hpubkey, &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Keypair generated by curve oid pub=#%lu priv=#%lu\n", hpubkey,
		 hprivkey);

	hkeys[0] = hpubkey;
	hkeys[1] = hprivkey;

	status = TEST_PASS;
end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		status = TEST_FAIL;

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int create_cipher_key(CK_FUNCTION_LIST_PTR pfunc,
			     CK_SESSION_HANDLE_PTR sess, CK_BBOOL token,
			     CK_OBJECT_HANDLE_PTR hkey)
{
	int status;

	CK_RV ret;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_BYTE key[32] = {};
	CK_BBOOL btrue = CK_TRUE;

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE, &key, sizeof(key) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
	};

	SUBTEST_START(status);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create %sKey Secret key\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(*sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Key secret created #%lu\n", *hkey);
	nb_aes_keys++;

	status = TEST_PASS;
end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		status = TEST_FAIL;

	SUBTEST_END(status);
	return status;
}

static int generate_cipher_key(CK_FUNCTION_LIST_PTR pfunc,
			       CK_SESSION_HANDLE_PTR sess, CK_BBOOL token,
			       CK_OBJECT_HANDLE_PTR hkey)
{
	int status;

	CK_RV ret;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_ULONG key_len = 16;
	CK_BBOOL btrue = CK_TRUE;

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
	};

	SUBTEST_START(status);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate %sCipher key\n", token ? "Token " : "");
	ret = pfunc->C_GenerateKey(*sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), hkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Key generated #%lu\n", *hkey);
	nb_aes_keys++;

	status = TEST_PASS;
end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		status = TEST_FAIL;

	SUBTEST_END(status);
	return status;
}

static int is_key_expected(CK_OBJECT_HANDLE_PTR hkey, CK_OBJECT_HANDLE_PTR hexp,
			   size_t nb_exp)
{
	size_t idx;

	for (idx = 0; idx < nb_exp; idx++)
		if (*hkey == hexp[idx])
			return 1;

	return 0;
}

static int find_all_keys(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE_PTR sess,
			 CK_OBJECT_HANDLE_PTR hkeys)
{
	int status;

	CK_RV ret;
	CK_OBJECT_HANDLE hkeys_match[NB_MAX_KEY + 1] = { 0 };
	CK_ULONG nb_match;
	CK_ULONG nb_keys_match = 0;
	CK_ULONG idx;
	int match;
	CK_OBJECT_CLASS key_class[] = { CKO_SECRET_KEY, CKO_PUBLIC_KEY,
					CKO_PRIVATE_KEY };
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_CLASS, NULL, sizeof(CK_OBJECT_CLASS) },
	};

	SUBTEST_START(status);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Find all keys\n");
	for (idx = 0; idx < ARRAY_SIZE(key_class); idx++) {
		match_attrs[0].pValue = &key_class[idx];

		ret = pfunc->C_FindObjectsInit(*sess, match_attrs,
					       ARRAY_SIZE(match_attrs));
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
			goto end;

		ret = pfunc->C_FindObjects(*sess, hkeys_match + nb_keys_match,
					   2, &nb_match);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
			goto end;
		nb_keys_match += nb_match;

		if (nb_match == 2) {
			ret = pfunc->C_FindObjects(*sess,
						   hkeys_match + nb_keys_match,
						   ARRAY_SIZE(hkeys_match) -
							   nb_keys_match,
						   &nb_match);
			if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
				goto end;
			nb_keys_match += nb_match;
		}

		ret = pfunc->C_FindObjectsFinal(*sess);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
			goto end;
	}

	if (CHECK_EXPECTED(nb_keys_match == NB_MAX_KEY,
			   "Got %lu but expected %u objects", nb_keys_match,
			   NB_MAX_KEY))
		goto end;

	/*
	 * Set return status as test Pass and force it to test Fail
	 * if one of the expected keys is not matching.
	 * Check all key array even to print out which keys are not
	 * matching.
	 */
	status = TEST_PASS;
	for (idx = 0; idx < NB_MAX_KEY; idx++) {
		match = is_key_expected(&hkeys_match[idx], hkeys, NB_MAX_KEY);
		if (CHECK_EXPECTED(match, "Key #%lu not expected",
				   hkeys_match[idx]))
			status = TEST_FAIL;
	}

end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		status = TEST_FAIL;

	SUBTEST_END(status);
	return status;
}

static int find_while_active(CK_FUNCTION_LIST_PTR pfunc,
			     CK_SESSION_HANDLE_PTR sess,
			     CK_OBJECT_HANDLE_PTR hkeys)
{
	int status;

	CK_RV ret;
	CK_OBJECT_HANDLE hkeys_match[NB_MAX_KEY + 1] = { 0 };
	CK_ULONG nb_match;
	CK_ULONG nb_keys_match = 0;
	CK_ULONG idx;
	int match;
	CK_OBJECT_CLASS key_class[] = { CKO_SECRET_KEY, CKO_PUBLIC_KEY,
					CKO_PRIVATE_KEY };
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_CLASS, NULL, sizeof(CK_OBJECT_CLASS) },
	};

	SUBTEST_START(status);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Find all keys\n");
	for (idx = 0; idx < ARRAY_SIZE(key_class); idx++) {
		match_attrs[0].pValue = &key_class[idx];

		ret = pfunc->C_FindObjectsInit(*sess, match_attrs,
					       ARRAY_SIZE(match_attrs));
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
			goto end;

		ret = pfunc->C_FindObjects(*sess, hkeys_match + nb_keys_match,
					   2, &nb_match);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
			goto end;
		nb_keys_match += nb_match;

		TEST_OUT("Start a new query while first not complete\n");
		ret = pfunc->C_FindObjectsInit(*sess, NULL, 0);
		if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_FindObjectsInit"))
			goto end;

		if (nb_match == 2) {
			ret = pfunc->C_FindObjects(*sess,
						   hkeys_match + nb_keys_match,
						   ARRAY_SIZE(hkeys_match) -
							   nb_keys_match,
						   &nb_match);
			if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
				goto end;
			nb_keys_match += nb_match;
		}

		ret = pfunc->C_FindObjectsFinal(*sess);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
			goto end;
	}

	if (CHECK_EXPECTED(nb_keys_match == NB_MAX_KEY,
			   "Got %lu but expected %u objects", nb_keys_match,
			   NB_MAX_KEY))
		goto end;

	/*
	 * Set return status as test Pass and force it to test Fail
	 * if one of the expected keys is not matching.
	 * Check all key array even to print out which keys are not
	 * matching.
	 */
	status = TEST_PASS;
	for (idx = 0; idx < NB_MAX_KEY; idx++) {
		match = is_key_expected(&hkeys_match[idx], hkeys, NB_MAX_KEY);
		if (CHECK_EXPECTED(match, "Key #%lu not expected",
				   hkeys_match[idx]))
			status = TEST_FAIL;
	}

end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		status = TEST_FAIL;

	SUBTEST_END(status);
	return status;
}

static int find_cipher_aes_keys(CK_FUNCTION_LIST_PTR pfunc,
				CK_SESSION_HANDLE_PTR sess,
				CK_OBJECT_HANDLE_PTR hkeys,
				CK_ULONG nb_keys_exp, CK_BBOOL token)
{
	int status;

	CK_RV ret;
	CK_OBJECT_HANDLE hkeys_match[NB_MAX_KEY + 1] = { 0 };
	CK_ULONG nb_match;
	CK_ULONG nb_keys_match;
	CK_ULONG idx;
	CK_KEY_TYPE key_type = CKK_AES;
	int match;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	SUBTEST_START(status);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Find Cipher AES %skeys\n", token ? "Token " : "");
	ret = pfunc->C_FindObjectsInit(*sess, match_attrs,
				       ARRAY_SIZE(match_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(*sess, hkeys_match, 2, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;
	nb_keys_match = nb_match;

	ret = pfunc->C_FindObjects(*sess, &hkeys_match[2],
				   ARRAY_SIZE(hkeys_match) - 2, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;
	nb_keys_match += nb_match;

	ret = pfunc->C_FindObjectsFinal(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_keys_match == nb_keys_exp,
			   "Got %lu but expected %zu objects", nb_keys_match,
			   nb_keys_exp))
		goto end;

	/*
	 * Set return status as test Pass and force it to test Fail
	 * if one of the expected keys is not matching.
	 * Check all key array even to print out which keys are not
	 * matching.
	 */
	status = TEST_PASS;
	for (idx = 0; idx < nb_keys_match; idx++) {
		match = is_key_expected(&hkeys_match[idx], hkeys, NB_MAX_KEY);
		if (CHECK_EXPECTED(match, "Key #%lu not expected",
				   hkeys_match[idx]))
			status = TEST_FAIL;
	}

end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		status = TEST_FAIL;

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_find(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	(void)lib_hdl;

	int status;

	CK_RV ret;
	CK_OBJECT_HANDLE hkeys[NB_MAX_KEY] = { 0 };
	CK_SESSION_HANDLE sess = 0;
	CK_C_INITIALIZE_ARGS init = { 0 };

	nb_aes_keys = 0;

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START(status);

	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (create_ec_key_public(pfunc, &sess, false, &hkeys[0]) == TEST_FAIL)
		goto end;

	if (create_ec_key_private(pfunc, &sess, false, &hkeys[1]) == TEST_FAIL)
		goto end;

	if (generate_ec_keypair(pfunc, &sess, false, &hkeys[2]) == TEST_FAIL)
		goto end;

	if (create_cipher_key(pfunc, &sess, false, &hkeys[4]) == TEST_FAIL)
		goto end;

	if (generate_cipher_key(pfunc, &sess, false, &hkeys[5]) == TEST_FAIL)
		goto end;

	if (create_cipher_key(pfunc, &sess, true, &hkeys[6]) == TEST_FAIL)
		goto end;

	if (generate_cipher_key(pfunc, &sess, true, &hkeys[7]) == TEST_FAIL)
		goto end;

	if (find_all_keys(pfunc, &sess, hkeys) == TEST_FAIL)
		goto end;

	if (find_cipher_aes_keys(pfunc, &sess, &hkeys[4], 2, false) ==
	    TEST_FAIL)
		goto end;

	if (find_cipher_aes_keys(pfunc, &sess, &hkeys[6], 2, true) == TEST_FAIL)
		goto end;

	status = find_while_active(pfunc, &sess, hkeys);

end:
	util_close_session(pfunc, &sess);

	ret = pfunc->C_Finalize(NULL);

	TEST_END(status);
}
