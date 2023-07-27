// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_session.h"

const CK_BYTE_PTR msg = (CK_BYTE_PTR) "messagetosign";
const CK_BYTE msg_sha256[] = { 0x2c, 0x3a, 0xd6, 0x43, 0xfd, 0x28, 0x47, 0xb5,
			       0xd6, 0x68, 0xf4, 0xc8, 0xcf, 0xbb, 0xbd, 0x89,
			       0x6c, 0xa4, 0xdb, 0xc8, 0xc0, 0xd2, 0x72, 0x70,
			       0x62, 0xa0, 0x5b, 0x06, 0x1f, 0x10, 0xe3, 0xba };
const CK_ULONG msg_sha256_len = 32;

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
	CK_ATTRIBUTE rsa_pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &rsa_modulus_bits, sizeof(CK_ULONG) },
	};
	CK_BBOOL rsa_sign = true;
	CK_ATTRIBUTE rsa_privkey_attrs[] = {
		{ CKA_SIGN, &rsa_sign, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

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
	CK_BBOOL rsa_verify = true;
	CK_ATTRIBUTE rsa_pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &rsa_modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &rsa_verify, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate RSA Keypair\n");
	ret = pfunc->C_GenerateKeyPair(sess, &rsa_key_mech, rsa_pubkey_attrs,
				       ARRAY_SIZE(rsa_pubkey_attrs), NULL_PTR,
				       0, &rsa_hpubkey, &rsa_hprivkey);

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
	CK_ULONG sign_len = 0;
	CK_ULONG data_len = 0;
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
	CK_ULONG sign_len = 0;
	CK_ULONG data_len = 0;
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

	TEST_OUT("Sign init with NULL mechanism");
	ret = pfunc->C_SignInit(sess, NULL, 1);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Verify init with NULL mechanism");
	ret = pfunc->C_VerifyInit(sess, NULL, 1);
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
	CK_BBOOL ec_verify = true;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = true;
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
					       ec_curves[0].name),
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
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA224 };
	CK_ULONG msg_len = strlen((const char *)msg);
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp = 0;

	CK_OBJECT_HANDLE hpubkey;
	CK_OBJECT_HANDLE hprivkey;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_BBOOL ec_verify = true;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = true;
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
					       ec_curves[0].name),
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
	ret = pfunc->C_Sign(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Sign"))
		goto end;

	/* Realloc signature buffer with new signature length */
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			      signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	/* Change mechanism, use already hashed message */
	sign_verify_mech.mechanism = CKM_ECDSA;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, (CK_BYTE_PTR)msg_sha256, msg_sha256_len,
			    signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, (CK_BYTE_PTR)msg_sha256, msg_sha256_len,
			      signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	signature_len *= 2;
	tmp = signature_len;
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign message with signature buffer bigger that needed\n");
	ret = pfunc->C_Sign(sess, (CK_BYTE_PTR)msg_sha256, msg_sha256_len,
			    signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Check updated signature buffer length\n");
	if (CHECK_EXPECTED(signature_len == (tmp / 2),
			   "Signature length not updated"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, (CK_BYTE_PTR)msg_sha256, msg_sha256_len,
			      signature, signature_len);
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

static int sign_verify_rsa(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA512_RSA_PKCS };
	CK_RSA_PKCS_PSS_PARAMS pss_params = { 0 };
	CK_ULONG msg_len = strlen((const char *)msg);
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_ULONG modulus_bits = 2048;
	CK_MECHANISM key_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_BBOOL sign = true;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &sign, sizeof(CK_BBOOL) },
	};
	CK_BBOOL verify = true;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &verify, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

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
	ret = pfunc->C_Sign(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			      signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	/* Change mechanism */
	sign_verify_mech.mechanism = CKM_RSA_PKCS_PSS;
	sign_verify_mech.pParameter = &pss_params;
	sign_verify_mech.ulParameterLen = sizeof(pss_params);
	pss_params.hashAlg = CKM_SHA384;
	pss_params.sLen = 100;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			      signature_len);
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

static int sign_verify_key_usage(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_ULONG msg_len = strlen((const char *)msg);
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey_sign = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey_sign = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hpubkey_verify = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey_verify = CK_INVALID_HANDLE;

	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_BBOOL ec_verify = CK_FALSE;
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

	TEST_OUT("Generate signature EC Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       ec_curves[0].name),
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
	ret = pfunc->C_Sign(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			    &signature_len);
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
	ret = pfunc->C_Verify(sess, (CK_BYTE_PTR)msg, msg_len, signature,
			      signature_len);
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
void tests_pkcs11_sign_verify(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
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

	ret = pfunc->C_Initialize(&init);
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

	if (sign_verify_key_usage(pfunc) == TEST_FAIL)
		goto end;

	status = sign_verify_rsa(pfunc);

end:
	ret = pfunc->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
