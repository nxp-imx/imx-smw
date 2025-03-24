// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
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

static CK_BYTE msg_sha512[] = {
	0xe6, 0x7e, 0xf4, 0x68, 0x5e, 0x8e, 0x06, 0x28, 0x20, 0x86, 0x9e,
	0xd8, 0x32, 0x56, 0xcf, 0xb5, 0xeb, 0x06, 0xb4, 0xa7, 0xf5, 0xa7,
	0x00, 0x56, 0x41, 0x2e, 0x9a, 0xaf, 0x1f, 0x4f, 0x7c, 0x0e, 0xd7,
	0x60, 0xb2, 0xae, 0xe6, 0x84, 0x5d, 0xe3, 0xd5, 0x38, 0xb4, 0xae,
	0x4e, 0x9c, 0x7f, 0x12, 0x85, 0x56, 0xa6, 0xc8, 0xa5, 0xc7, 0x99,
	0xbf, 0x68, 0x72, 0x69, 0x8d, 0x00, 0x48, 0x42, 0x55
};

static CK_ULONG msg_sha512_len = 64;

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

static int sign_verify_multipart_eddsa(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp_len = 0;
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
		  sizeof(key_allowed_mech) }
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

	if (!util_lib_is_mech_supported(pfunc, 0, key_allowed_mech[0])) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Generate EC Keypair by curve name\n");
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

		TEST_OUT("Sign the message first part\n");
		ret = pfunc->C_SignUpdate(sess, payload, payload_len);
		if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
			goto end;

		TEST_OUT("Get signature length\n");
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
		ret = pfunc->C_VerifyInit(sess, &sign_verify_mech[idx],
					  hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
			goto end;

		TEST_OUT("Verify the message first part\n");
		ret = pfunc->C_VerifyUpdate(sess, payload, payload_len);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
			goto end;

		TEST_OUT("Finish multi-part verify operation\n");
		ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
			goto end;

		tmp_len = signature_len;
		signature_len *= 2;
		signature = realloc(signature, signature_len);
		if (CHECK_EXPECTED(signature, "Allocation error"))
			goto end;

		TEST_OUT("Initialize sign operation\n");
		ret = pfunc->C_SignInit(sess, &sign_verify_mech[idx], hprivkey);
		if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
			goto end;

		TEST_OUT("Sign the message first part\n");
		ret = pfunc->C_SignUpdate(sess, payload, payload_len);
		if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
			goto end;

		TEST_OUT("Get signature length\n");
		ret = pfunc->C_SignFinal(sess, NULL_PTR, &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
			goto end;

		TEST_OUT("Check updated signature buffer length\n");
		if (CHECK_EXPECTED(signature_len == tmp_len,
				   "Signature length not updated"))
			goto end;

		TEST_OUT("Finish multi-part sign operation\n");
		ret = pfunc->C_SignFinal(sess, signature, &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
			goto end;

		TEST_OUT("Initialize verify operation\n");
		ret = pfunc->C_VerifyInit(sess, &sign_verify_mech[idx],
					  hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
			goto end;

		TEST_OUT("Verify the message first part\n");
		ret = pfunc->C_VerifyUpdate(sess, payload, payload_len);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
			goto end;

		TEST_OUT("Finish multi-part verify operation\n");
		ret = pfunc->C_VerifyFinal(sess, signature, signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
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

	if (status != TEST_SKIP)
		status = TEST_FAIL;
	else
		status = TEST_PASS;

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

	if (sign_verify_multipart_eddsa(pfunc) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
