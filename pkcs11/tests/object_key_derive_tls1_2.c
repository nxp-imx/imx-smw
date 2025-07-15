// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"

static CK_BYTE peer_buffer[] = {
	0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7,
	0x02, 0x70, 0x39, 0x8c, 0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc,
	0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63, 0x56,
	0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c,
	0x13, 0xc5, 0x8d, 0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f,
	0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab
};

static CK_BYTE client_random[] = { 0x2e, 0xf5, 0xf5, 0x95, 0x3a, 0xe3, 0x91,
				   0x8a, 0x6c, 0xef, 0x3d, 0x51, 0x14, 0x06,
				   0xe9, 0xa0, 0x2c, 0x65, 0x26, 0x16, 0xd7,
				   0x8f, 0x68, 0xc7, 0x0f, 0x0e, 0x21, 0x69,
				   0xa7, 0x86, 0x4d, 0xbe };

static CK_BYTE server_random[] = { 0x12, 0xd4, 0xd9, 0x0c, 0x3c, 0x89, 0xce,
				   0x1d, 0x50, 0x2a, 0x6a, 0xa2, 0x43, 0x6c,
				   0xb3, 0x2f, 0xb4, 0x98, 0xb0, 0x94, 0x8f,
				   0x63, 0xa5, 0xd0, 0x5c, 0x41, 0x3c, 0xe4,
				   0xa3, 0x42, 0xeb, 0x8d };

static CK_BYTE session_hash[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				  0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04,
				  0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
				  0x0c, 0x0d, 0x0e, 0x0f };

static int object_derive_key_tls12_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = {
		CKM_TLS12_MASTER_KEY_DERIVE_DH
	};
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) },
	};

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_TLS12_MASTER_KEY_DERIVE_PARAMS tls12_master_params = { 0 };
	CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS
	tls12_extended_master_params = { 0 };
	CK_TLS12_KEY_MAT_PARAMS tls12_block_params = { 0 };
	CK_MECHANISM tls12_mech = { CKM_TLS12_MASTER_KEY_DERIVE_DH,
				    (void *)&tls12_master_params,
				    sizeof(tls12_master_params) };

	CK_OBJECT_CLASS derive_key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = {
		CKM_TLS12_KEY_AND_MAC_DERIVE
	};
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = {
		CKM_TLS12_MASTER_KEY_DERIVE_DH
	};
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};
	CK_SSL3_KEY_MAT_OUT key_material = { 0 };
	CK_BYTE client_iv[20] = { 0 };
	CK_BYTE server_iv[20] = { 0 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech) ||
	    !util_lib_is_mech_supported(pfunc, 0, ecdhe_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	TEST_OUT("Generate a base key\n");
	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Set CKM_ECDH1_DERIVE mechanism parameters\n");
	ecdh_params.kdf = CKD_NULL;
	ecdh_params.pSharedData = NULL;
	ecdh_params.ulSharedDataLen = 0;
	ecdh_params.pPublicData = peer_buffer;
	ecdh_params.ulPublicDataLen = ARRAY_SIZE(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");

	tls12_mech.mechanism = CKM_ECDSA;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Null TLS12 mechanism parameter\n");
	tls12_mech.mechanism = CKM_TLS12_MASTER_KEY_DERIVE_DH;
	tls12_mech.pParameter = NULL;
	tls12_mech.ulParameterLen = 0;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid TLS12 mechanism parameter length\n");
	tls12_mech.mechanism = CKM_TLS12_MASTER_KEY_DERIVE_DH;
	tls12_mech.pParameter = &tls12_master_params;
	tls12_mech.ulParameterLen = 1;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Random buffers set but with length=0\n");
	tls12_mech.ulParameterLen = sizeof(tls12_master_params);
	tls12_master_params.prfHashMechanism = CKM_SHA256;
	tls12_master_params.pVersion = NULL;
	tls12_master_params.RandomInfo.pClientRandom = client_random;
	tls12_master_params.RandomInfo.pServerRandom = server_random;
	tls12_master_params.RandomInfo.ulClientRandomLen = 0;
	tls12_master_params.RandomInfo.ulServerRandomLen = 0;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("Random buffers NULL but with valid length\n");
	tls12_master_params.prfHashMechanism = CKM_SHA256;
	tls12_master_params.pVersion = NULL;
	tls12_master_params.RandomInfo.pClientRandom = NULL;
	tls12_master_params.RandomInfo.ulClientRandomLen =
		sizeof(client_random);
	tls12_master_params.RandomInfo.pServerRandom = NULL;
	tls12_master_params.RandomInfo.ulServerRandomLen =
		sizeof(server_random);
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_TLS12_MASTER_DERIVE mechanism parameters\n");
	tls12_master_params.prfHashMechanism = CKM_SHA256;
	tls12_master_params.pVersion = NULL;
	tls12_master_params.RandomInfo.pClientRandom = client_random;
	tls12_master_params.RandomInfo.pServerRandom = server_random;
	tls12_master_params.RandomInfo.ulClientRandomLen =
		sizeof(client_random);
	tls12_master_params.RandomInfo.ulServerRandomLen =
		sizeof(server_random);

	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Null TLS12 mechanism parameter\n");
	tls12_mech.mechanism = CKM_TLS12_KEY_AND_MAC_DERIVE;
	tls12_mech.pParameter = NULL;
	tls12_mech.ulParameterLen = 0;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, derived_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL_PTR);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid TLS12 mechanism parameter length\n");
	tls12_mech.pParameter = &tls12_block_params;
	tls12_mech.ulParameterLen = 1;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, derived_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL_PTR);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Random buffers NULL but with valid length\n");
	tls12_mech.pParameter = &tls12_block_params;
	tls12_mech.ulParameterLen = sizeof(tls12_block_params);
	tls12_block_params.prfHashMechanism = CKM_SHA256;
	tls12_block_params.bIsExport = false;
	tls12_block_params.RandomInfo.pClientRandom = NULL;
	tls12_block_params.RandomInfo.pServerRandom = NULL;
	tls12_block_params.RandomInfo.ulClientRandomLen = sizeof(client_random);
	tls12_block_params.RandomInfo.ulServerRandomLen = sizeof(server_random);
	tls12_block_params.ulIVSizeInBits =
		BYTES_TO_BITS(ARRAY_SIZE(client_iv));
	tls12_block_params.ulKeySizeInBits = 160;
	tls12_block_params.ulMacSizeInBits = 256;
	tls12_block_params.pReturnedKeyMaterial = &key_material;
	key_material.pIVClient = client_iv;
	key_material.pIVServer = server_iv;

	derived_key_allowed_mech = CKM_AES_CBC;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, derived_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("Random buffers set but with length=0\n");
	tls12_block_params.RandomInfo.pClientRandom = client_random;
	tls12_block_params.RandomInfo.pServerRandom = server_random;
	tls12_block_params.RandomInfo.ulClientRandomLen = 0;
	tls12_block_params.RandomInfo.ulServerRandomLen = 0;

	ret = pfunc->C_DeriveKey(sess, &tls12_mech, derived_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("Returned key material is set to NULL\n");
	tls12_block_params.RandomInfo.ulClientRandomLen = sizeof(client_random);
	tls12_block_params.RandomInfo.ulServerRandomLen = sizeof(server_random);
	tls12_block_params.pReturnedKeyMaterial = NULL;

	ret = pfunc->C_DeriveKey(sess, &tls12_mech, derived_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("Null TLS12 mechanism parameter\n");
	tls12_mech.mechanism = CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH;
	tls12_mech.pParameter = NULL;
	tls12_mech.ulParameterLen = 0;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid TLS12 mechanism parameter length\n");
	tls12_mech.mechanism = CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH;
	tls12_mech.pParameter = &tls12_extended_master_params;
	tls12_mech.ulParameterLen = 1;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("session hash set but with length=0\n");
	tls12_mech.ulParameterLen = sizeof(tls12_extended_master_params);
	tls12_extended_master_params.prfHashMechanism = CKM_SHA256;
	tls12_extended_master_params.pVersion = NULL;
	tls12_extended_master_params.pSessionHash = session_hash;
	tls12_extended_master_params.ulSessionHashLen = 0;
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	TEST_OUT("session hash NULL but with valid length\n");
	tls12_extended_master_params.prfHashMechanism = CKM_SHA256;
	tls12_extended_master_params.pVersion = NULL;
	tls12_extended_master_params.pSessionHash = NULL;
	tls12_extended_master_params.ulSessionHashLen = sizeof(session_hash);
	ret = pfunc->C_DeriveKey(sess, &tls12_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_tls12(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = {
		CKM_TLS12_MASTER_KEY_DERIVE_DH
	};
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) },
	};

	CK_TLS12_MASTER_KEY_DERIVE_PARAMS tls12_master_params = { 0 };
	CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS
	tls12_extended_master_params = { 0 };
	CK_MECHANISM tls12_master_mech = { CKM_TLS12_MASTER_KEY_DERIVE_DH,
					   (void *)&tls12_master_params,
					   sizeof(tls12_master_params) };
	CK_MECHANISM tls12_extended_master_mech = {
		CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
		(void *)&tls12_extended_master_params,
		sizeof(tls12_extended_master_params)
	};
	CK_TLS12_KEY_MAT_PARAMS tls12_block_params = { 0 };
	CK_SSL3_KEY_MAT_OUT key_material = { 0 };
	CK_BYTE client_iv[20] = { 0 };
	CK_BYTE server_iv[20] = { 0 };
	CK_MECHANISM tls12_block_mech = { CKM_TLS12_KEY_AND_MAC_DERIVE,
					  (void *)&tls12_block_params,
					  sizeof(tls12_block_params) };

	CK_OBJECT_CLASS derive_key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = {
		CKM_TLS12_KEY_AND_MAC_DERIVE
	};
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = {
		CKM_TLS12_MASTER_KEY_DERIVE_DH
	};
	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech) ||
	    !util_lib_is_mech_supported(pfunc, 0, derived_key_allowed_mech) ||
	    !util_lib_is_mech_supported(pfunc, 0, ecdhe_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	TEST_OUT("Generate a base key\n");
	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Set CKM_ECDH1_DERIVE mechanism parameters\n");
	ecdh_params.kdf = CKD_NULL;
	ecdh_params.pSharedData = NULL;
	ecdh_params.ulSharedDataLen = 0;
	ecdh_params.pPublicData = peer_buffer;
	ecdh_params.ulPublicDataLen = ARRAY_SIZE(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_TLS12_MASTER_DERIVE mechanism parameters\n");
	tls12_master_params.prfHashMechanism = CKM_SHA256;
	tls12_master_params.pVersion = NULL;
	tls12_master_params.RandomInfo.pClientRandom = client_random;
	tls12_master_params.RandomInfo.pServerRandom = server_random;
	tls12_master_params.RandomInfo.ulClientRandomLen =
		sizeof(client_random);
	tls12_master_params.RandomInfo.ulServerRandomLen =
		sizeof(server_random);

	ret = pfunc->C_DeriveKey(sess, &tls12_master_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_TLS12_KEY_AND_MAC_DERIVE mechanism parameters\n");
	tls12_block_params.prfHashMechanism = CKM_SHA256;
	tls12_block_params.bIsExport = false;
	tls12_block_params.RandomInfo.pClientRandom = client_random;
	tls12_block_params.RandomInfo.pServerRandom = server_random;
	tls12_block_params.RandomInfo.ulClientRandomLen = sizeof(client_random);
	tls12_block_params.RandomInfo.ulServerRandomLen = sizeof(server_random);
	tls12_block_params.ulIVSizeInBits =
		BYTES_TO_BITS(ARRAY_SIZE(client_iv));
	tls12_block_params.ulKeySizeInBits = 160;
	tls12_block_params.ulMacSizeInBits = 256;
	tls12_block_params.pReturnedKeyMaterial = &key_material;
	key_material.pIVClient = client_iv;
	key_material.pIVServer = server_iv;

	derived_key_type = CKK_AES;
	derived_key_allowed_mech = CKM_AES_CBC;
	ret = pfunc->C_DeriveKey(sess, &tls12_block_mech, derived_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Delete the client key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hClientKey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the client MAC key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hClientMacSecret);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the server key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hServerKey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the server MAC key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hServerMacSecret);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the derived key\n");
	ret = pfunc->C_DestroyObject(sess, derived_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Set CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH mech params\n");
	tls12_extended_master_params.prfHashMechanism = CKM_SHA256;
	tls12_extended_master_params.pVersion = NULL;
	tls12_extended_master_params.pSessionHash = session_hash;
	tls12_extended_master_params.ulSessionHashLen = sizeof(session_hash);

	derived_key_allowed_mech = CKM_TLS12_KEY_AND_MAC_DERIVE;
	derived_key_type = CKK_GENERIC_SECRET;
	ret = pfunc->C_DeriveKey(sess, &tls12_extended_master_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_TLS12_KEY_AND_MAC_DERIVE mechanism parameters\n");
	tls12_block_params.prfHashMechanism = CKM_SHA256;
	tls12_block_params.bIsExport = false;
	tls12_block_params.RandomInfo.pClientRandom = client_random;
	tls12_block_params.RandomInfo.pServerRandom = server_random;
	tls12_block_params.RandomInfo.ulClientRandomLen = sizeof(client_random);
	tls12_block_params.RandomInfo.ulServerRandomLen = sizeof(server_random);
	tls12_block_params.ulIVSizeInBits =
		BYTES_TO_BITS(ARRAY_SIZE(client_iv));
	tls12_block_params.ulKeySizeInBits = 160;
	tls12_block_params.ulMacSizeInBits = 256;
	tls12_block_params.pReturnedKeyMaterial = &key_material;
	key_material.pIVClient = client_iv;
	key_material.pIVServer = server_iv;

	derived_key_type = CKK_AES;
	derived_key_allowed_mech = CKM_AES_CBC;
	ret = pfunc->C_DeriveKey(sess, &tls12_block_mech, derived_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Delete the client key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hClientKey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the client MAC key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hClientMacSecret);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the server key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hServerKey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the server MAC key\n");
	ret = pfunc->C_DestroyObject(sess, key_material.hServerMacSecret);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the derived key\n");
	ret = pfunc->C_DestroyObject(sess, derived_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the ecdhe key\n");
	ret = pfunc->C_DestroyObject(sess, ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hpubkey);
	ret = pfunc->C_DestroyObject(sess, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hprivkey);
	ret = pfunc->C_DestroyObject(sess, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_derive_key_tls1_2(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (object_derive_key_tls12_bad_param(pfunc) == TEST_FAIL)
		goto end;

	status = object_derive_key_tls12(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
