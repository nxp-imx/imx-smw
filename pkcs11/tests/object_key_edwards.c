// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <asn1_ec_curve.h>

#include <smw_status.h>
#include <smw/object.h>

#include "os_mutex.h"
#include "util_session.h"
#include "util.h"

/*
 * Max supported EC Edwards private key size is 448 bits
 */
#define MAX_PRIVATE_KEY_LEN 56

#define SMW_SIGN_EDDSA(_curve, _hash, _param)                                  \
	SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA(                              \
		SMW_ATTR_CURVE_##_curve, SMW_ATTR_HASH_##_hash,                \
		SMW_ATTR_SIGN_PARAM_EDDSA_##_param)

#define EC_STR_ED25519 "ed25519"

const CK_BYTE ed25519[] = ASN1_OID_ED25519;

const struct asn1_ec_curve ed_curves[] = {
	[EC_ED25519] = { 255, EC_STR_ED25519, ed25519, sizeof(ed25519) },
};

static int object_edwards_key_public(CK_FUNCTION_LIST_PTR pfunc, CK_BBOOL token,
				     CK_BBOOL bverify)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_EC_EDWARDS;
	CK_BYTE_PTR pubkey = NULL;
	CK_ULONG pubkey_len = 0;
	size_t security_size = 0;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_EDDSA };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_EC_POINT, NULL_PTR, 0 },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &bverify, sizeof(bverify) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	for (; i < ARRAY_SIZE(ed_curves); i++) {
		/* Set the CKA_EC_POINT size function of the security size */
		security_size = ed_curves[i].security_size;
		pubkey_len = BITS_TO_BYTES_SIZE(security_size);

		if (pubkey)
			free(pubkey);

		pubkey = calloc(1, pubkey_len);
		if (CHECK_EXPECTED(pubkey, "Out of memory"))
			goto end;

		keyTemplate[3].pValue = pubkey;
		keyTemplate[3].ulValueLen = pubkey_len;

		TEST_OUT("Create %sKey Public by curve name\n",
			 token ? "Token " : "");
		if (CHECK_EXPECTED(util_to_asn1_string(&keyTemplate[2],
						       &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		ret = pfunc->C_CreateObject(sess, keyTemplate,
					    ARRAY_SIZE(keyTemplate), &hkey);

		free(keyTemplate[2].pValue);
		keyTemplate[2].pValue = NULL;

		if (bverify || !token) {
			if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
				goto end;

			TEST_OUT("Key public by curve name created #%lu\n",
				 hkey);

			TEST_OUT("Key Destroy #%lu\n", hkey);
			ret = pfunc->C_DestroyObject(sess, hkey);
			if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
				goto end;
		} else {
			if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_CreateObject"))
				goto end;
		}

		TEST_OUT("Create %sKey Public by curve oid\n",
			 token ? "Token " : "");

		if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2],
						    &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		ret = pfunc->C_CreateObject(sess, keyTemplate,
					    ARRAY_SIZE(keyTemplate), &hkey);

		free(keyTemplate[2].pValue);
		keyTemplate[2].pValue = NULL;

		if (bverify || !token) {
			if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
				goto end;

			TEST_OUT("Key public created by curve oid #%lu\n",
				 hkey);

			TEST_OUT("Key Destroy #%lu\n", hkey);
			ret = pfunc->C_DestroyObject(sess, hkey);
			if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
				goto end;
		} else {
			if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_CreateObject"))
				goto end;
		}
	}

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	if (pubkey)
		free(pubkey);

	SUBTEST_END(status);
	return status;
}

static int object_edwards_key_private(CK_FUNCTION_LIST_PTR pfunc,
				      CK_BBOOL token, CK_BBOOL bsign)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_EC_EDWARDS;
	CK_BYTE privkey[MAX_PRIVATE_KEY_LEN] = { 0 };
	CK_BYTE_PTR pubkey = NULL;
	CK_ULONG pubkey_len = 0;
	size_t security_size = 0;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_EDDSA };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VALUE, &privkey, sizeof(privkey) },
		{ CKA_EC_POINT, NULL_PTR, 0 },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &bsign, sizeof(bsign) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(ed_curves); i++) {
		TEST_OUT("Create %sKey Private by curve name\n",
			 token ? "Token " : "");
		if (CHECK_EXPECTED(util_to_asn1_string(&keyTemplate[2],
						       &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		/* Set the CKA_EC_POINT size according to the security size */
		security_size = ed_curves[i].security_size;
		pubkey_len = BITS_TO_BYTES_SIZE(security_size);

		if (pubkey)
			free(pubkey);

		pubkey = calloc(1, pubkey_len);
		if (CHECK_EXPECTED(pubkey, "Out of memory"))
			goto end;

		keyTemplate[4].pValue = pubkey;
		keyTemplate[4].ulValueLen = pubkey_len;

		/* Set the CKA_VALUE size according to the security size */
		keyTemplate[3].ulValueLen = BITS_TO_BYTES_SIZE(security_size);
		ret = pfunc->C_CreateObject(sess, keyTemplate,
					    ARRAY_SIZE(keyTemplate), &hkey);

		free(keyTemplate[2].pValue);
		keyTemplate[2].pValue = NULL;

		if (bsign || !token) {
			if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
				goto end;

			TEST_OUT("Key private by curve name created #%lu\n",
				 hkey);

			TEST_OUT("Key Destroy #%lu\n", hkey);
			ret = pfunc->C_DestroyObject(sess, hkey);
			if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
				goto end;
		} else {
			if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_CreateObject"))
				goto end;
		}

		TEST_OUT("Create %sKey Private by curve oid\n",
			 token ? "Token " : "");

		if (CHECK_EXPECTED(util_to_asn1_oid(&keyTemplate[2],
						    &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		ret = pfunc->C_CreateObject(sess, keyTemplate,
					    ARRAY_SIZE(keyTemplate), &hkey);

		free(keyTemplate[2].pValue);
		keyTemplate[2].pValue = NULL;

		if (bsign || !token) {
			if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
				goto end;

			TEST_OUT("Key private created by curve oid #%lu\n",
				 hkey);

			TEST_OUT("Key Destroy #%lu\n", hkey);
			ret = pfunc->C_DestroyObject(sess, hkey);
			if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
				goto end;
		} else {
			if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_CreateObject"))
				goto end;
		}
	}

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	if (keyTemplate[2].pValue)
		free(keyTemplate[2].pValue);

	if (pubkey)
		free(pubkey);

	SUBTEST_END(status);
	return status;
}

static int object_generate_edwards_keypair(CK_FUNCTION_LIST_PTR pfunc,
					   CK_BBOOL token)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN };
	CK_BBOOL bverify = CK_TRUE;
	CK_BBOOL bsign = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_EDDSA };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &bverify, sizeof(bverify) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &bsign, sizeof(bsign) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(ed_curves); i++) {
		TEST_OUT("Generate %sKeypair by curve name\n",
			 token ? "Token " : "");
		if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
						       &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
					       ARRAY_SIZE(pubkey_attrs),
					       privkey_attrs,
					       ARRAY_SIZE(privkey_attrs),
					       &hpubkey, &hprivkey);

		free(pubkey_attrs[0].pValue);
		pubkey_attrs[0].pValue = NULL;

		if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
			goto end;

		TEST_OUT("Keypair generated by curve name pub=#%lu priv=#%lu\n",
			 hpubkey, hprivkey);

		TEST_OUT("Key Destroy #%lu\n", hpubkey);
		ret = pfunc->C_DestroyObject(sess, hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		TEST_OUT("Key Destroy #%lu\n", hprivkey);
		ret = pfunc->C_DestroyObject(sess, hprivkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		TEST_OUT("Generate %sKeypair by curve oid\n",
			 token ? "Token " : "");

		if (CHECK_EXPECTED(util_to_asn1_oid(&pubkey_attrs[0],
						    &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
					       ARRAY_SIZE(pubkey_attrs),
					       privkey_attrs,
					       ARRAY_SIZE(privkey_attrs),
					       &hpubkey, &hprivkey);

		free(pubkey_attrs[0].pValue);
		pubkey_attrs[0].pValue = NULL;

		if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
			goto end;

		TEST_OUT("Keypair generated by curve oid pub=#%lu priv=#%lu\n",
			 hpubkey, hprivkey);

		TEST_OUT("Key Destroy #%lu\n", hpubkey);
		ret = pfunc->C_DestroyObject(sess, hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		TEST_OUT("Key Destroy #%lu\n", hprivkey);
		ret = pfunc->C_DestroyObject(sess, hprivkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int object_edwards_keypair_usage(CK_FUNCTION_LIST_PTR pfunc,
					CK_BBOOL token)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN };
	CK_BBOOL bverify = CK_FALSE;
	CK_BBOOL bsign = CK_FALSE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_EDDSA };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &bverify, sizeof(bverify) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &bsign, sizeof(bsign) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(ed_curves); i++) {
		TEST_OUT("Generate %sKeypair no usage by curve name\n",
			 token ? "Token " : "");
		if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
						       &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		bsign = CK_FALSE;
		bverify = CK_FALSE;

		ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
					       ARRAY_SIZE(pubkey_attrs),
					       privkey_attrs,
					       ARRAY_SIZE(privkey_attrs),
					       &hpubkey, &hprivkey);

		if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GenerateKeyPair"))
			goto end;

		TEST_OUT("Generate %sKeypair sign only usage by curve name\n",
			 token ? "Token " : "");

		bsign = CK_TRUE;

		ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
					       ARRAY_SIZE(pubkey_attrs),
					       privkey_attrs,
					       ARRAY_SIZE(privkey_attrs),
					       &hpubkey, &hprivkey);

		if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
			goto end;

		TEST_OUT("Generate %sKeypair verify only usage by curve name\n",
			 token ? "Token " : "");

		TEST_OUT("Key Destroy #%lu\n", hpubkey);
		ret = pfunc->C_DestroyObject(sess, hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		TEST_OUT("Key Destroy #%lu\n", hprivkey);
		ret = pfunc->C_DestroyObject(sess, hprivkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		bsign = CK_FALSE;
		bverify = CK_TRUE;

		ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
					       ARRAY_SIZE(pubkey_attrs),
					       privkey_attrs,
					       ARRAY_SIZE(privkey_attrs),
					       &hpubkey, &hprivkey);

		if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
			goto end;

		TEST_OUT("Key Destroy #%lu\n", hpubkey);
		ret = pfunc->C_DestroyObject(sess, hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		TEST_OUT("Key Destroy #%lu\n", hprivkey);
		ret = pfunc->C_DestroyObject(sess, hprivkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		free(pubkey_attrs[0].pValue);
		pubkey_attrs[0].pValue = NULL;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int object_edwards_public_export(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_generate_key_args genkey_args = { 0 };
	struct smw_delete_key_args delkey_args = { 0 };
	struct smw_key_attributes key_attributes = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	CK_RV ret = CKR_OK;
	CK_BBOOL btrue = CK_TRUE;
	CK_SESSION_HANDLE sess = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_ULONG nb_match = 0;

	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL;
	CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
	CK_BYTE_PTR ec_point = NULL;
	CK_ULONG ec_point_len = 0;

	CK_ATTRIBUTE public_key_attrs[] = {
		{ CKA_CLASS, &public_key_class, sizeof(public_key_class) },
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	CK_ATTRIBUTE getkeyAttr[] = {
		{ CKA_EC_POINT, NULL_PTR, 0 },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Set key attributes */
	key_descriptor.type_name = SMW_KEY_TYPE_NAME_ED25519;
	key_descriptor.security_size = 255;
	key_attributes.attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;
	key_attributes.permitted_algo = SMW_SIGN_EDDSA(ED25519, NONE, NONE);
	key_attributes.usage_flags =
		SMW_ATTR_USAGE_SIGN_MESSAGE | SMW_ATTR_USAGE_VERIFY_MESSAGE;

	genkey_args.key_descriptor = &key_descriptor;
	genkey_args.key_attributes = &key_attributes;
	delkey_args.key_descriptor = &key_descriptor;

	/* Generate a key pair with SMW API */
	smw_status = smw_generate_key(&genkey_args);
	if (smw_status != SMW_STATUS_OK &&
	    smw_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		TEST_OUT("Generate key pair failed\n");
		goto end;
	}

	ret = util_set_unique_id(unique_id, &unique_id_len, public_key_class,
				 key_descriptor.id);
	if (ret != CKR_BUFFER_TOO_SMALL) {
		TEST_OUT("Get unique id len failed\n");
		goto end;
	}

	unique_id = calloc(1, unique_id_len);
	if (!unique_id) {
		TEST_OUT("Out of memory\n");
		goto end;
	}

	ret = util_set_unique_id(unique_id, &unique_id_len, public_key_class,
				 key_descriptor.id);
	if (ret != CKR_OK) {
		TEST_OUT("Set unique id failed\n");
		goto end;
	}

	public_key_attrs[1].pValue = unique_id;
	public_key_attrs[1].ulValueLen = unique_id_len;

	/* Retrieve public key generated with SMW API */
	TEST_OUT("Find EC public key\n");
	ret = pfunc->C_FindObjectsInit(sess, public_key_attrs,
				       ARRAY_SIZE(public_key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hpubkey, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	TEST_OUT("Get Public key attribute length\n");
	ret = pfunc->C_GetAttributeValue(sess, hpubkey, getkeyAttr,
					 ARRAY_SIZE(getkeyAttr));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	ec_point_len = getkeyAttr[0].ulValueLen;

	TEST_OUT("Get Public key attribute\n");
	if (CHECK_EXPECTED(ec_point_len, "Invalid public key length"))
		goto end;

	ec_point = calloc(1, ec_point_len);
	if (CHECK_EXPECTED(ec_point, "Out of memory"))
		goto end;

	getkeyAttr[0].pValue = ec_point;
	ret = pfunc->C_GetAttributeValue(sess, hpubkey, getkeyAttr,
					 ARRAY_SIZE(getkeyAttr));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	status = TEST_PASS;

end:
	if (hpubkey) {
		TEST_OUT("Key Destroy #%lu\n", hpubkey);
		ret = pfunc->C_DestroyObject(sess, hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	/* Destroy the key */
	if (key_descriptor.id)
		smw_delete_key(&delkey_args);

	if (unique_id)
		free(unique_id);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_object_key_edwards(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (object_edwards_key_public(pfunc, CK_FALSE, CK_TRUE) == TEST_FAIL)
		goto end;

	if (object_edwards_key_public(pfunc, CK_FALSE, CK_FALSE) == TEST_FAIL)
		goto end;

	if (object_edwards_key_private(pfunc, CK_FALSE, CK_TRUE) == TEST_FAIL)
		goto end;

	if (object_edwards_key_private(pfunc, CK_FALSE, CK_FALSE) == TEST_FAIL)
		goto end;

	if (object_generate_edwards_keypair(pfunc, CK_FALSE) == TEST_FAIL)
		goto end;

	if (object_edwards_keypair_usage(pfunc, CK_FALSE) == TEST_FAIL)
		goto end;

	if (object_edwards_key_public(pfunc, CK_TRUE, CK_TRUE) == TEST_FAIL)
		goto end;

	if (object_edwards_key_public(pfunc, CK_TRUE, CK_FALSE) == TEST_FAIL)
		goto end;

	if (object_edwards_key_private(pfunc, CK_TRUE, CK_TRUE) == TEST_FAIL)
		goto end;

	if (object_edwards_key_private(pfunc, CK_TRUE, CK_FALSE) == TEST_FAIL)
		goto end;

	if (object_generate_edwards_keypair(pfunc, CK_TRUE) == TEST_FAIL)
		goto end;

	if (object_edwards_public_export(pfunc) == TEST_FAIL)
		goto end;

	status = object_edwards_keypair_usage(pfunc, CK_TRUE);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
