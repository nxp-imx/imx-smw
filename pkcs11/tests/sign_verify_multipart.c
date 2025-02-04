// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"

/* messagetosign */
static CK_BYTE msg[] = { 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
			 0x74, 0x6f, 0x73, 0x69, 0x67, 0x6e };

static CK_ULONG msg_len = 13;

static int sign_verify_multipart_no_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE signature[1] = { 0 };
	CK_ULONG signature_len = 1;

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

	TEST_OUT("Sign update without init\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_SignUpdate"))
		goto end;

	TEST_OUT("Sign final without init\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_SignFinal"))
		goto end;

	TEST_OUT("Verify update without init\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Verify final without init\n");
	ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_multipart_wrong_order(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = { { CKA_EC_PARAMS, NULL_PTR, 0 },
					{ CKA_VERIFY, &ec_verify,
					  sizeof(CK_BBOOL) } };
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

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

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Perform single-part sign intervening multi-part\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Sign"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	/* Alloc signature buffer with new signature length */
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Finish multi-part sign operation\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Perform single-part sign\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Sign the message first part without init\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_SignUpdate"))
		goto end;

	TEST_OUT("Finish multi-part sign operation without init\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_SignFinal"))
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

static int verify_multipart_wrong_order(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = { { CKA_EC_PARAMS, NULL_PTR, 0 },
					{ CKA_VERIFY, &ec_verify,
					  sizeof(CK_BBOOL) } };
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

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

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	/* Alloc signature buffer with new signature length */
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

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Perform single-part verify interrupting multi-part\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Verify"))
		goto end;

	TEST_OUT("Finish multi-part verify operation\n");
	ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Perform single-part verify\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	TEST_OUT("Verify the message first part without init\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Finish multi-part verify operation without init\n");
	ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyFinal"))
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

static int sign_verify_multipart_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE signature[1] = { 0 };
	CK_ULONG signature_len = 1;

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = { { CKA_EC_PARAMS, NULL_PTR, 0 },
					{ CKA_VERIFY, &ec_verify,
					  sizeof(CK_BBOOL) } };
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

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

	TEST_OUT("Session's handle is NULL\n");
	ret = pfunc->C_SignUpdate(0, msg, msg_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_SignUpdate"))
		goto end;

	TEST_OUT("Pointer to message is NULL\n");
	ret = pfunc->C_SignUpdate(sess, NULL_PTR, msg_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_SignUpdate"))
		goto end;

	TEST_OUT("Message length is 0\n");
	ret = pfunc->C_SignUpdate(sess, msg, 0);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_SignUpdate"))
		goto end;

	TEST_OUT("Pointer to hold length of the signature is NULL\n");
	ret = pfunc->C_SignFinal(sess, signature, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_SignFinal"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Session's handle is NULL\n");
	ret = pfunc->C_VerifyUpdate(0, msg, msg_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Pointer to message is NULL\n");
	ret = pfunc->C_VerifyUpdate(sess, NULL_PTR, msg_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Message length is 0\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, 0);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Pointer to signature is NULL\n");
	ret = pfunc->C_VerifyFinal(sess, NULL_PTR, signature_len);
	if (CHECK_CK_RV(CKR_SIGNATURE_INVALID, "C_VerifyFinal"))
		goto end;

	TEST_OUT("Signature length is 0\n");
	ret = pfunc->C_VerifyFinal(sess, signature, 0);
	if (CHECK_CK_RV(CKR_SIGNATURE_LEN_RANGE, "C_VerifyFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_cancel_op(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = { { CKA_EC_PARAMS, NULL_PTR, 0 },
					{ CKA_VERIFY, &ec_verify,
					  sizeof(CK_BBOOL) } };
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

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

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Cancel on-going multi-part sign operation\n");
	ret = pfunc->C_SignInit(sess, NULL_PTR, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign the message first part without init\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_SignUpdate"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Cancel on-going multi-part verify operation\n");
	ret = pfunc->C_VerifyInit(sess, NULL_PTR, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part without init\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyUpdate"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_multipart_ecdsa(CK_FUNCTION_LIST_PTR pfunc)
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
	CK_ATTRIBUTE pubkey_attrs[] = { { CKA_EC_PARAMS, NULL_PTR, 0 },
					{ CKA_VERIFY, &ec_verify,
					  sizeof(CK_BBOOL) } };
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

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

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	/* Alloc signature buffer with new signature length */
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Finish multi-part sign operation\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Finish multi-part verify operation\n");
	ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
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

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignFinal(sess, NULL_PTR, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	TEST_OUT("Check updated signature buffer length\n");
	if (CHECK_EXPECTED(signature_len == tmp,
			   "Signature length not updated"))
		goto end;

	TEST_OUT("Finish multi-part sign operation\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Finish multi-part verify operation\n");
	ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
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

static int sign_verify_multipart_rsa_pkcs(CK_FUNCTION_LIST_PTR pfunc)
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
	CK_ATTRIBUTE privkey_attrs[] = { { CKA_SIGN, &sign, sizeof(CK_BBOOL) },
					 { CKA_ALLOWED_MECHANISMS,
					   &key_allowed_mech,
					   sizeof(key_allowed_mech) } };
	CK_BBOOL verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &verify, sizeof(CK_BBOOL) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
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

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	/* Alloc signature buffer with new signature length */
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Finish multi-part sign operation\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Finish multi-part verify operation\n");
	ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_multipart_rsa_pss(CK_FUNCTION_LIST_PTR pfunc)
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
	CK_ATTRIBUTE privkey_attrs[] = { { CKA_SIGN, &sign, sizeof(CK_BBOOL) },
					 { CKA_ALLOWED_MECHANISMS,
					   &key_allowed_mech,
					   sizeof(key_allowed_mech) } };
	CK_BBOOL verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &verify, sizeof(CK_BBOOL) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
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
	pss_params.sLen = 100;

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

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	/* Alloc signature buffer with new signature length */
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Finish multi-part sign operation\n");
	ret = pfunc->C_SignFinal(sess, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Finish multi-part verify operation\n");
	ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (signature)
		free(signature);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_multipart_cmac(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_AES_CMAC };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_CMAC };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ULONG key_length = 32;
	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_SignUpdate"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_VerifyUpdate"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_multipart_hmac(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA256_HMAC };

	CK_OBJECT_HANDLE hmac_hsecretkey = 0;
	CK_MECHANISM hmac_key_mech = { .mechanism =
					       CKM_GENERIC_SECRET_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_KEY_TYPE secret_key_type = CKK_SHA256_HMAC;
	CK_ULONG key_length = 32;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_HMAC };

	CK_ATTRIBUTE hmac_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}
	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &hmac_key_mech, hmac_secretkey_attrs,
				   ARRAY_SIZE(hmac_secretkey_attrs),
				   &hmac_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hmac_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_SignUpdate"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hmac_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(sess, msg, msg_len);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_VerifyUpdate"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_sign_verify_multipart(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (sign_verify_multipart_no_init(pfunc) == TEST_FAIL)
		goto end;

	if (sign_multipart_wrong_order(pfunc) == TEST_FAIL)
		goto end;

	if (verify_multipart_wrong_order(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multipart_bad_param(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_cancel_op(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multipart_ecdsa(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multipart_rsa_pkcs(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multipart_rsa_pss(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multipart_cmac(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_multipart_hmac(pfunc) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
