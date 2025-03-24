// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"

/* Message to sign */
static CK_BYTE msg[] = {
	0x29, 0xac, 0xb0, 0xfc, 0xa2, 0x7e, 0x2a, 0x10, 0xd7, 0xb9, 0xe7, 0xe8,
	0x4a, 0x79, 0xaf, 0x73, 0xe4, 0x20, 0xab, 0xdb, 0x0f, 0x80, 0xdd, 0x26,
	0x65, 0x69, 0x66, 0x38, 0x95, 0x1b, 0x52, 0xdd, 0x39, 0xca, 0x02, 0x81,
	0x66, 0xb4, 0x7a, 0x3b, 0x6a, 0x2e, 0xae, 0xce, 0xb1, 0xa1, 0x1c, 0x15,
	0x23, 0x83, 0xf0, 0xbe, 0xc6, 0x4e, 0x86, 0x2d, 0xb1, 0xc2, 0x49, 0x67,
	0x2b, 0x37, 0x70, 0x90, 0x9f, 0x77, 0x5b, 0x79, 0x4e, 0x0b, 0x9b, 0x28,
	0xa5, 0xec, 0x86, 0x35, 0xa9, 0x96, 0xd9, 0x12, 0xd8, 0x37, 0xa5, 0xf2,
	0x24, 0x71, 0xb4, 0x0e, 0xc2, 0xe8, 0x47, 0x01, 0xa8, 0x80, 0x41, 0x27,
	0xa9, 0xf1, 0xa0, 0xb3, 0xc9, 0x6f, 0xf6, 0x54, 0x70, 0x0b, 0xad, 0x31,
	0x67, 0x24, 0x0c, 0x25, 0x18, 0xfb, 0x5d, 0xed, 0xcc, 0x1b, 0xe9, 0xf5,
	0x6a, 0x80, 0x70, 0x83, 0xe5, 0x87, 0xbc, 0x56,
};

static CK_ULONG msg_len = 128;

static CK_BYTE msg_sha256[] = {
	0xd1, 0x5f, 0xa5, 0xd0, 0xd1, 0x95, 0xca, 0xff, 0x1d, 0x67, 0xc8,
	0xcd, 0x5a, 0xc0, 0xc5, 0x14, 0xcd, 0xdf, 0xdc, 0x54, 0x3f, 0xd0,
	0xa0, 0x79, 0x2d, 0x85, 0x80, 0x9e, 0xb0, 0xd7, 0x7d, 0x1a
};

static CK_ULONG msg_sha256_len = 32;

static CK_BYTE msg_sha512[] = {
	0xe6, 0x7e, 0xf4, 0x68, 0x5e, 0x8e, 0x06, 0x28, 0x20, 0x86, 0x9e,
	0xd8, 0x32, 0x56, 0xcf, 0xb5, 0xeb, 0x06, 0xb4, 0xa7, 0xf5, 0xa7,
	0x00, 0x56, 0x41, 0x2e, 0x9a, 0xaf, 0x1f, 0x4f, 0x7c, 0x0e, 0xd7,
	0x60, 0xb2, 0xae, 0xe6, 0x84, 0x5d, 0xe3, 0xd5, 0x38, 0xb4, 0xae,
	0x4e, 0x9c, 0x7f, 0x12, 0x85, 0x56, 0xa6, 0xc8, 0xa5, 0xc7, 0x99,
	0xbf, 0x68, 0x72, 0x69, 0x8d, 0x00, 0x48, 0x42, 0x55
};

static CK_ULONG msg_sha512_len = 64;

static int sign_init_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_mech = { 0 };
	CK_RSA_PKCS_PSS_PARAMS pss_params = { 0 };

	CK_OBJECT_HANDLE rsa_hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE rsa_hprivkey = CK_INVALID_HANDLE;
	CK_ULONG rsa_modulus_bits = 2048;
	CK_MECHANISM rsa_key_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_RSA_PKCS_PSS };
	CK_ATTRIBUTE rsa_pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &rsa_modulus_bits, sizeof(CK_ULONG) },
	};
	CK_BBOOL rsa_sign = CK_TRUE;
	CK_ATTRIBUTE rsa_privkey_attrs[] = {
		{ CKA_SIGN, &rsa_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, rsa_key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate RSA Keypair\n");
	ret = pfunc->C_GenerateKeyPair(sess, &rsa_key_mech, rsa_pubkey_attrs,
				       ARRAY_SIZE(rsa_pubkey_attrs),
				       rsa_privkey_attrs,
				       ARRAY_SIZE(rsa_privkey_attrs),
				       &rsa_hpubkey, &rsa_hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_SignInit(0, &sign_mech, 0);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_SignInit"))
		goto end;

	TEST_OUT("Check key handle NULL\n");
	ret = pfunc->C_SignInit(sess, &sign_mech, 0);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_SignInit"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	sign_mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	ret = pfunc->C_SignInit(sess, &sign_mech, rsa_hprivkey);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_SignInit"))
		goto end;

	TEST_OUT("Check CKA_SIGN key flag\n");
	sign_mech.mechanism = CKM_RSA_PKCS;
	ret = pfunc->C_SignInit(sess, &sign_mech, rsa_hpubkey);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_SignInit"))
		goto end;

	TEST_OUT("Check bad RSA PSS mechanism parameters:\n");
	TEST_OUT("Bad hash algorithm (mechanism type with hash algorithm)\n");
	sign_mech.mechanism = CKM_SHA1_RSA_PKCS_PSS;
	sign_mech.pParameter = &pss_params;
	sign_mech.ulParameterLen = sizeof(pss_params);
	pss_params.hashAlg = CKM_SHA224;
	ret = pfunc->C_SignInit(sess, &sign_mech, rsa_hprivkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_SignInit"))
		goto end;

	TEST_OUT("Bad MGF (mechanism type with hash algorithm)\n");
	pss_params.hashAlg = CKM_SHA_1;
	pss_params.mgf = CKG_MGF1_SHA224;
	ret = pfunc->C_SignInit(sess, &sign_mech, rsa_hprivkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_SignInit"))
		goto end;

	TEST_OUT("Hash algorithm differs from MGF ");
	TEST_OUT("(mechanism type without hash algorithm)\n");
	sign_mech.mechanism = CKM_RSA_PKCS_PSS;
	ret = pfunc->C_SignInit(sess, &sign_mech, rsa_hprivkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_SignInit"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int verify_init_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM verify_mech = { 0 };
	CK_RSA_PKCS_PSS_PARAMS pss_params = { 0 };

	CK_OBJECT_HANDLE rsa_hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE rsa_hprivkey = CK_INVALID_HANDLE;
	CK_ULONG rsa_modulus_bits = 2048;
	CK_MECHANISM rsa_key_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_RSA_PKCS_PSS };
	CK_BBOOL rsa_verify = CK_TRUE;
	CK_ATTRIBUTE rsa_pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &rsa_modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &rsa_verify, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE rsa_privkey_attrs[] = {
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, rsa_key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate RSA Keypair\n");
	ret = pfunc->C_GenerateKeyPair(sess, &rsa_key_mech, rsa_pubkey_attrs,
				       ARRAY_SIZE(rsa_pubkey_attrs),
				       rsa_privkey_attrs,
				       ARRAY_SIZE(rsa_privkey_attrs),
				       &rsa_hpubkey, &rsa_hprivkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_VerifyInit(0, &verify_mech, 0);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_VerifyInit"))
		goto end;

	TEST_OUT("Check key handle NULL\n");
	ret = pfunc->C_VerifyInit(sess, &verify_mech, 0);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_VerifyInit"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	verify_mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	ret = pfunc->C_VerifyInit(sess, &verify_mech, rsa_hpubkey);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_VerifyInit"))
		goto end;

	TEST_OUT("Check CKA_VERIFY key flag\n");
	verify_mech.mechanism = CKM_RSA_PKCS;
	ret = pfunc->C_VerifyInit(sess, &verify_mech, rsa_hprivkey);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_VerifyInit"))
		goto end;

	TEST_OUT("Check bad RSA PSS mechanism parameters:\n");
	TEST_OUT("Bad hash algorithm (mechanism type with hash algorithm)\n");
	verify_mech.mechanism = CKM_SHA1_RSA_PKCS_PSS;
	verify_mech.pParameter = &pss_params;
	verify_mech.ulParameterLen = sizeof(pss_params);
	pss_params.hashAlg = CKM_SHA224;
	ret = pfunc->C_VerifyInit(sess, &verify_mech, rsa_hpubkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_VerifyInit"))
		goto end;

	TEST_OUT("Bad MGF (mechanism type with hash algorithm)\n");
	pss_params.hashAlg = CKM_SHA_1;
	pss_params.mgf = CKG_MGF1_SHA224;
	ret = pfunc->C_VerifyInit(sess, &verify_mech, rsa_hpubkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_VerifyInit"))
		goto end;

	TEST_OUT("Hash algorithm differs from MGF ");
	TEST_OUT("(mechanism type without hash algorithm)\n");
	verify_mech.mechanism = CKM_RSA_PKCS_PSS;
	ret = pfunc->C_VerifyInit(sess, &verify_mech, rsa_hpubkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_VerifyInit"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG data_len = 0;
	CK_ULONG sign_len = 0;
	CK_BYTE data[5] = { 0 };
	CK_BYTE signature[32] = { 0 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	sign_len = sizeof(signature);
	data_len = sizeof(data);

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_Sign(0, data, data_len, signature, &sign_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Sign"))
		goto end;

	TEST_OUT("Check signature length pointer NULL\n");
	ret = pfunc->C_Sign(sess, data, data_len, signature, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Sign"))
		goto end;

	TEST_OUT("Check data pointer NULL\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, data_len, signature, &sign_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Sign"))
		goto end;

	TEST_OUT("Check data length 0\n");
	ret = pfunc->C_Sign(sess, data, 0, signature, &sign_len);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Sign"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int verify_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG data_len = 0;
	CK_ULONG sign_len = 0;
	CK_BYTE data[5] = { 0 };
	CK_BYTE signature[32] = { 0 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	sign_len = sizeof(signature);
	data_len = sizeof(data);

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_Verify(0, data, data_len, signature, sign_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Verify"))
		goto end;

	TEST_OUT("Check data pointer NULL\n");
	ret = pfunc->C_Verify(sess, NULL_PTR, data_len, signature, sign_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Verify"))
		goto end;

	TEST_OUT("Check data length 0\n");
	ret = pfunc->C_Verify(sess, data, 0, signature, sign_len);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Verify"))
		goto end;

	TEST_OUT("Check signature pointer NULL\n");
	ret = pfunc->C_Verify(sess, data, data_len, NULL_PTR, sign_len);
	if (CHECK_CK_RV(CKR_SIGNATURE_INVALID, "C_Verify"))
		goto end;

	TEST_OUT("Check signature length 0\n");
	ret = pfunc->C_Verify(sess, data, data_len, signature, 0);
	if (CHECK_CK_RV(CKR_SIGNATURE_LEN_RANGE, "C_Verify"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_no_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG sign_len = 0;
	CK_ULONG data_len = 0;
	CK_BYTE data[5] = { 0 };
	CK_BYTE signature[32] = { 0 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Sign init with NULL mechanism");
	ret = pfunc->C_SignInit(sess, NULL_PTR, 1);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Verify init with NULL mechanism");
	ret = pfunc->C_VerifyInit(sess, NULL_PTR, 1);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	sign_len = sizeof(signature);
	data_len = sizeof(data);

	TEST_OUT("Sign without init\n");
	ret = pfunc->C_Sign(sess, data, data_len, signature, &sign_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Sign"))
		goto end;

	TEST_OUT("Verify without init\n");
	ret = pfunc->C_Verify(sess, data, data_len, signature, sign_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Verify"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_multiple_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA224 };

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate EC Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_192]),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Check multiple sign init with same mechanism\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_SignInit"))
		goto end;

	TEST_OUT("Check multiple sign init with different mechanism\n");
	sign_verify_mech.mechanism = CKM_ECDSA_SHA256;
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_SignInit"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Check multiple verify init with same mechanism\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_VerifyInit"))
		goto end;

	TEST_OUT("Check multiple verify init with different mechanism\n");
	sign_verify_mech.mechanism = CKM_ECDSA_SHA224;
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_VerifyInit"))
		goto end;

	TEST_OUT("Check multiple sign init with NULL mechanism\n");
	ret = pfunc->C_SignInit(sess, NULL_PTR, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Check multiple verify init with NULL mechanism\n");
	ret = pfunc->C_VerifyInit(sess, NULL_PTR, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_ecdsa(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp = 0;

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate EC Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	/* Set a wrong signature length */
	signature_len = 20;
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign message with signature buffer too small\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Sign"))
		goto end;

	/* Realloc signature buffer with new signature length */
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	/* Change mechanism, use already hashed message */
	sign_verify_mech.mechanism = CKM_ECDSA;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, msg_sha256, msg_sha256_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg_sha256, msg_sha256_len, signature,
			      signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	tmp = signature_len;
	signature_len *= 2;
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign message with signature buffer bigger that needed\n");
	ret = pfunc->C_Sign(sess, msg_sha256, msg_sha256_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Check updated signature buffer length\n");
	if (CHECK_EXPECTED(signature_len == tmp,
			   "Signature length not updated"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg_sha256, msg_sha256_len, signature,
			      signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_rsa_pkcs(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA512_RSA_PKCS };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_ULONG modulus_bits = 2048;
	CK_MECHANISM key_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA512_RSA_PKCS };
	CK_BBOOL sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_BBOOL verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &verify, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate RSA Keypair\n");
	ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_rsa_pss(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_RSA_PKCS_PSS };
	CK_RSA_PKCS_PSS_PARAMS pss_params = { 0 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_ULONG modulus_bits = 2048;
	CK_MECHANISM key_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA384_RSA_PKCS_PSS };
	CK_BBOOL sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_BBOOL verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &verify, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	sign_verify_mech.pParameter = &pss_params;
	sign_verify_mech.ulParameterLen = sizeof(pss_params);
	pss_params.hashAlg = CKM_SHA384;
	pss_params.sLen = 48;

	TEST_OUT("Generate RSA Keypair\n");
	ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_ed25519(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_BYTE_PTR payload = NULL_PTR;
	CK_ULONG payload_len = 0;

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_EDDSA };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_BYTE context[] = { 0, 1, 2, 3, 4, 5 };
	CK_EDDSA_PARAMS_PTR params = NULL_PTR;
	CK_EDDSA_PARAMS mech_param[] = {
		{ 0 },
		{ .phFlag = CK_TRUE },
		{ .pContextData = context,
		  .ulContextDataLen = 256 }, /* Error */
		{ .pContextData = context, .ulContextDataLen = sizeof(context) }
	};
	CK_MECHANISM sign_verify_mech[] = {
		{ .mechanism = CKM_EDDSA },
		{ .mechanism = CKM_EDDSA,
		  .pParameter = &mech_param[0],
		  .ulParameterLen = sizeof(mech_param[0]) },
		{ .mechanism = CKM_EDDSA,
		  .pParameter = &mech_param[1],
		  .ulParameterLen = sizeof(mech_param[1]) },
		{ .mechanism = CKM_EDDSA,
		  .pParameter = &mech_param[2],
		  .ulParameterLen = sizeof(mech_param[2]) },
		{ .mechanism = CKM_EDDSA,
		  .pParameter = &mech_param[3],
		  .ulParameterLen = sizeof(mech_param[3]) }
	};

	size_t idx = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate Edwards Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ed_curves[EC_ED25519]),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	for (; idx < ARRAY_SIZE(sign_verify_mech); idx++) {
		params = sign_verify_mech[idx].pParameter;

		TEST_OUT("Initialize sign operation\n");
		ret = pfunc->C_SignInit(sess, &sign_verify_mech[idx], hprivkey);
		if (params && params->ulContextDataLen > 255) {
			if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID,
					"C_SignInit"))
				goto end;

			continue;
		} else {
			if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
				goto end;
		}

		payload = msg;
		payload_len = msg_len;

		if (params && params->phFlag) {
			payload = msg_sha512;
			payload_len = msg_sha512_len;
		}

		/* Set a wrong signature length */
		signature_len = 20;
		signature = malloc(signature_len);
		if (CHECK_EXPECTED(signature, "Allocation error"))
			goto end;

		TEST_OUT("Sign message with signature buffer too small\n");
		ret = pfunc->C_Sign(sess, payload, payload_len, signature,
				    &signature_len);
		if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Sign"))
			goto end;

		/* Realloc signature buffer with new signature length */
		signature = realloc(signature, signature_len);
		if (CHECK_EXPECTED(signature, "Allocation error"))
			goto end;

		TEST_OUT("Sign message\n");
		ret = pfunc->C_Sign(sess, payload, payload_len, signature,
				    &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_Sign"))
			goto end;

		TEST_OUT("Initialize verify operation\n");
		ret = pfunc->C_VerifyInit(sess, &sign_verify_mech[idx],
					  hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
			goto end;

		TEST_OUT("Verify signature\n");
		ret = pfunc->C_Verify(sess, payload, payload_len, signature,
				      signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_Verify"))
			goto end;

		free(signature);
		signature = NULL;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_key_usage(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey_sign = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey_sign = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hpubkey_verify = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey_verify = CK_INVALID_HANDLE;

	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_FALSE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate signature EC Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey_sign,
				       &hprivkey_sign);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Generate verification EC Keypair by curve name\n");
	ec_sign = CK_FALSE;
	ec_verify = CK_TRUE;
	ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs),
				       &hpubkey_verify, &hprivkey_verify);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Initialize sign operation with non sign private key\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey_verify);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_SignInit"))
		goto end;

	TEST_OUT("Initialize sign operation with sign private key\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey_sign);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	signature_len = 64;
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation with non verify public key\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey_sign);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_VerifyInit"))
		goto end;

	TEST_OUT("Initialize verify operation with a bad verify public key\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey_verify);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature with public key no verify usage\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_SIGNATURE_INVALID, "C_Verify"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_sign_verify(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (sign_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (verify_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (sign_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (verify_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_no_init(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multiple_init(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_ecdsa(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_rsa_pkcs(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_rsa_pss(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_ed25519(pfunc) == TEST_FAIL)
		goto end;

	status = sign_verify_key_usage(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
