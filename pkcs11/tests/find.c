// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <asn1_ec_curve.h>

#include "os_mutex.h"
#include "util.h"
#include "util_session.h"

#define NB_MAX_KEYS_HDL 9

static int create_ec_key_public(CK_FUNCTION_LIST_PTR pfunc,
				CK_SESSION_HANDLE_PTR sess, CK_BBOOL token,
				CK_OBJECT_HANDLE_PTR hkey,
				CK_ULONG *nb_key_created)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE pubkey[67] = { 0 };
	CK_BBOOL btrue = CK_TRUE;
	CK_ULONG ec_point_size = 0;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_EC_POINT, &pubkey, sizeof(pubkey) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	*nb_key_created = 0;

	/* Set the CKA_EC_POINT size function of the security size */
	if (MUL_OVERFLOW(BITS_TO_BYTES_SIZE(192), 2, &ec_point_size) ||
	    INC_OVERFLOW(ec_point_size, 1))
		goto end;

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04;	   /* octet string tag */
	pubkey[1] = ec_point_size; /* EC point size */
	pubkey[2] = 0x04;	   /* Uncompress point */

	keyTemplate[3].ulValueLen = ec_point_size + 2;

	TEST_OUT("Create %sKey Public by curve oid\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2],
					    &ec_curves[SECP_R1_192]),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_CreateObject(*sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key public created by curve oid #%lu\n", *hkey);

	*nb_key_created = 1;
	status = TEST_PASS;
end:
	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	SUBTEST_END(status);
	return status;
}

static int create_ec_key_private(CK_FUNCTION_LIST_PTR pfunc,
				 CK_SESSION_HANDLE_PTR sess, CK_BBOOL token,
				 CK_OBJECT_HANDLE_PTR hkey,
				 CK_ULONG *nb_key_created)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BYTE privkey[32] = { 0 };
	CK_BYTE pubkey[67] = { 0 };
	CK_BBOOL btrue = CK_TRUE;
	CK_ULONG ec_point_size = 0;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VALUE, &privkey, sizeof(privkey) },
		{ CKA_EC_POINT, &pubkey, sizeof(pubkey) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	*nb_key_created = 0;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create %sKey Private by curve oid\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2],
					    &ec_curves[SECP_R1_192]),
			   "ASN1 Conversion"))
		goto end;

	/* Set the CKA_VALUE size function of the security size */
	keyTemplate[3].ulValueLen = BITS_TO_BYTES_SIZE(192);

	/* Set the CKA_EC_POINT size function of the security size */
	if (MUL_OVERFLOW(BITS_TO_BYTES_SIZE(192), 2, &ec_point_size) ||
	    INC_OVERFLOW(ec_point_size, 1))
		goto end;

	/*
	 * Set EC Public point
	 */
	pubkey[0] = 0x04;	   /* octet string tag */
	pubkey[1] = ec_point_size; /* EC point size */
	pubkey[2] = 0x04;	   /* Uncompress point */

	/* Set the CKA_EC_POINT size function of the security size */
	keyTemplate[4].ulValueLen = ec_point_size + 2;

	ret = pfunc->C_CreateObject(*sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;
	TEST_OUT("Key private created by curve oid #%lu\n", *hkey);

	*nb_key_created = 1;
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
			       CK_OBJECT_HANDLE_PTR hkeys,
			       CK_ULONG *nb_key_created)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	*nb_key_created = 0;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate %sKeypair by curve oid\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_oid(&pubkey_attrs[0],
					    &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(*sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Keypair generated by curve oid pub=#%lu priv=#%lu\n", hpubkey,
		 hprivkey);

	hkeys[0] = hpubkey;
	hkeys[1] = hprivkey;

	*nb_key_created = 2;
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
			     CK_OBJECT_HANDLE_PTR hkey,
			     CK_ULONG *nb_key_created)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_BYTE key[32] = { 0 };
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_ECB };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE, &key, sizeof(key) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	*nb_key_created = 0;

	/*
	 * Plaintext token key import is not supported on ELE and SECO.
	 * Only session key import is supported.
	 */
	if (!is_tee_subsystem() && token) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create %sKey Secret key\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(*sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    hkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Key secret created #%lu\n", *hkey);

	*nb_key_created = 1;
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
			       CK_OBJECT_HANDLE_PTR hkey,
			       CK_ULONG *nb_key_created)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_ULONG key_len = 16;
	CK_BBOOL btrue = CK_TRUE;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_ECB };

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	*nb_key_created = 0;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate %sCipher key\n", token ? "Token " : "");
	ret = pfunc->C_GenerateKey(*sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), hkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Key generated #%lu\n", *hkey);

	*nb_key_created = 1;
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
	for (size_t idx = 0; idx < nb_exp; idx++)
		if (hexp[idx] != CK_INVALID_HANDLE && *hkey == hexp[idx])
			return 1;

	return 0;
}

static int find_all_keys(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE_PTR sess,
			 CK_OBJECT_HANDLE_PTR hkeys, CK_ULONG keys_counter)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE hkeys_match[NB_MAX_KEYS_HDL] = { 0 };
	CK_ULONG nb_match = 0;
	CK_ULONG nb_keys_match = 0;
	CK_ULONG nb_max_obj = 0;
	CK_ULONG idx = 0;
	int match = 0;
	CK_OBJECT_CLASS key_class[] = { CKO_SECRET_KEY, CKO_PUBLIC_KEY,
					CKO_PRIVATE_KEY };
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_CLASS, NULL_PTR, sizeof(CK_OBJECT_CLASS) },
	};

	SUBTEST_START();

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL_PTR, 0);
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

		if (INC_OVERFLOW(nb_keys_match, nb_match))
			goto end;

		if (nb_match == 2) {
			if (SUB_OVERFLOW(ARRAY_SIZE(hkeys_match), nb_keys_match,
					 &nb_max_obj))
				goto end;

			ret = pfunc->C_FindObjects(*sess,
						   hkeys_match + nb_keys_match,
						   nb_max_obj, &nb_match);
			if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
				goto end;

			if (INC_OVERFLOW(nb_keys_match, nb_match))
				goto end;
		}

		ret = pfunc->C_FindObjectsFinal(*sess);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
			goto end;
	}

	if (CHECK_EXPECTED(nb_keys_match == keys_counter,
			   "Got %lu but expected %lu objects", nb_keys_match,
			   keys_counter))
		goto end;

	/*
	 * Set return status as test Pass and force it to test Fail
	 * if one of the expected keys is not matching.
	 * Check all key array even to print out which keys are not
	 * matching.
	 */
	status = TEST_PASS;
	for (idx = 0; idx < keys_counter; idx++) {
		match = is_key_expected(&hkeys_match[idx], hkeys, keys_counter);
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
			     CK_OBJECT_HANDLE_PTR hkeys, CK_ULONG keys_counter)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE hkeys_match[NB_MAX_KEYS_HDL] = { 0 };
	CK_ULONG nb_match = 0;
	CK_ULONG nb_keys_match = 0;
	CK_ULONG idx = 0;
	int match = 0;
	CK_OBJECT_CLASS key_class[] = { CKO_SECRET_KEY, CKO_PUBLIC_KEY,
					CKO_PRIVATE_KEY };
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_CLASS, NULL_PTR, sizeof(CK_OBJECT_CLASS) },
	};

	SUBTEST_START();

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL_PTR, 0);
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

		if (INC_OVERFLOW(nb_keys_match, nb_match))
			goto end;

		TEST_OUT("Start a new query while first not complete\n");
		ret = pfunc->C_FindObjectsInit(*sess, NULL_PTR, 0);
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

			if (INC_OVERFLOW(nb_keys_match, nb_match))
				goto end;
		}

		ret = pfunc->C_FindObjectsFinal(*sess);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
			goto end;
	}

	if (CHECK_EXPECTED(nb_keys_match == keys_counter,
			   "Got %lu but expected %lu objects", nb_keys_match,
			   keys_counter))
		goto end;

	/*
	 * Set return status as test Pass and force it to test Fail
	 * if one of the expected keys is not matching.
	 * Check all key array even to print out which keys are not
	 * matching.
	 */
	status = TEST_PASS;
	for (idx = 0; idx < keys_counter; idx++) {
		match = is_key_expected(&hkeys_match[idx], hkeys, keys_counter);
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
				CK_ULONG nb_keys_exp, CK_BBOOL token,
				CK_ULONG keys_counter)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE hkeys_match[NB_MAX_KEYS_HDL] = { 0 };
	CK_ULONG nb_match = 0;
	CK_ULONG nb_keys_match = 0;
	CK_ULONG idx = 0;
	CK_KEY_TYPE key_type = CKK_AES;
	int match = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL_PTR, 0);
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

	if (INC_OVERFLOW(nb_keys_match, nb_match))
		goto end;

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
		match = is_key_expected(&hkeys_match[idx], hkeys, keys_counter);
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

void tests_pkcs11_find(void *lib_hdl, CK_VOID_PTR pfunc)
{
	(void)lib_hdl;

	int status = TEST_FAIL;
	unsigned int i = 0;

	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE hkeys[NB_MAX_KEYS_HDL] = { 0 };
	CK_SESSION_HANDLE sess = 0;
	CK_C_INITIALIZE_ARGS init = { 0 };
	CK_ULONG keys_counter = 0;
	CK_ULONG idx_aes_key_not_token = 0;
	CK_ULONG idx_aes_key_token = 0;
	CK_ULONG nb_key_created = 0;
	CK_ULONG nb_aes_not_token_key = 0;
	CK_ULONG nb_aes_token_key = 0;

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START();

	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (create_ec_key_public(pfunc, &sess, CK_FALSE, &hkeys[keys_counter],
				 &nb_key_created) == TEST_FAIL)
		goto end;
	keys_counter += nb_key_created;

	if (create_ec_key_private(pfunc, &sess, CK_FALSE, &hkeys[keys_counter],
				  &nb_key_created) == TEST_FAIL)
		goto end;
	keys_counter += nb_key_created;

	if (generate_ec_keypair(pfunc, &sess, CK_FALSE, &hkeys[keys_counter],
				&nb_key_created) == TEST_FAIL)
		goto end;
	keys_counter += nb_key_created;

	if (create_cipher_key(pfunc, &sess, CK_FALSE, &hkeys[keys_counter],
			      &nb_key_created) == TEST_FAIL)
		goto end;

	if (nb_key_created) {
		idx_aes_key_not_token = keys_counter;
		nb_aes_not_token_key = nb_key_created;
	}

	keys_counter += nb_key_created;

	if (generate_cipher_key(pfunc, &sess, CK_FALSE, &hkeys[keys_counter],
				&nb_key_created) == TEST_FAIL)
		goto end;

	if (nb_key_created) {
		if (!idx_aes_key_not_token)
			idx_aes_key_not_token = keys_counter;

		nb_aes_not_token_key += nb_key_created;
	}

	keys_counter += nb_key_created;

	if (create_cipher_key(pfunc, &sess, CK_TRUE, &hkeys[keys_counter],
			      &nb_key_created) == TEST_FAIL)
		goto end;

	if (nb_key_created) {
		idx_aes_key_token = keys_counter;
		nb_aes_token_key = nb_key_created;
	}

	keys_counter += nb_key_created;

	if (generate_cipher_key(pfunc, &sess, CK_TRUE, &hkeys[keys_counter],
				&nb_key_created) == TEST_FAIL)
		goto end;

	if (nb_key_created) {
		if (!idx_aes_key_token)
			idx_aes_key_token = keys_counter;

		nb_aes_token_key += nb_key_created;
	}

	keys_counter += nb_key_created;

	if (find_all_keys(pfunc, &sess, hkeys, keys_counter) == TEST_FAIL)
		goto end;

	if (find_cipher_aes_keys(pfunc, &sess, &hkeys[idx_aes_key_not_token],
				 nb_aes_not_token_key, CK_FALSE,
				 keys_counter) == TEST_FAIL)
		goto end;

	if (find_cipher_aes_keys(pfunc, &sess, &hkeys[idx_aes_key_token],
				 nb_aes_token_key, CK_TRUE,
				 keys_counter) == TEST_FAIL)
		goto end;

	status = find_while_active(pfunc, &sess, hkeys, keys_counter);

end:
	TEST_OUT("Login to R/W Session as User\n");
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)
		      ->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login")) {
		status = TEST_FAIL;
		goto error;
	}

	for (; i < NB_MAX_KEYS_HDL; i++) {
		if (hkeys[i] != CK_INVALID_HANDLE)
			(void)((CK_FUNCTION_LIST_PTR)pfunc)
				->C_DestroyObject(sess, hkeys[i]);
	}

error:
	util_close_session(pfunc, &sess);

	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
