// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"
#include "util_digest.h"

static int digest_multipart_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE key = 0;
	CK_MECHANISM dig_mech = { 0 };
	CK_BYTE digest[32] = { 0 };
	CK_ULONG digest_length = 32;
	enum mechanism_id id = MECH_ID_SHA256;

	CK_BYTE rsa_modulus[256] = { 0 };
	CK_BYTE rsa_pub_exp[] = { 0x01, 0x00, 0x01 };
	CK_OBJECT_HANDLE rsa_pub_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE rsa_allowed_mech = CKM_SHA512_RSA_PKCS;
	CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_RSA;

	CK_ATTRIBUTE public_key_template[] = {
		{ CKA_CLASS, &public_key_class, sizeof(public_key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_MODULUS, (CK_BYTE_PTR)rsa_modulus, sizeof(rsa_modulus) },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exp,
		  sizeof(rsa_pub_exp) },
		{ CKA_ALLOWED_MECHANISMS, &rsa_allowed_mech,
		  sizeof(rsa_allowed_mech) }
	};

	CK_MECHANISM_TYPE aes_allowed_mech = CKM_AES_ECB;
	CK_OBJECT_HANDLE aes_key = 0;
	/* AES - 256 bits key length */
	CK_ULONG key_length = 32;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &aes_allowed_mech,
		  sizeof(aes_allowed_mech) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	dig_mech.mechanism = DIGEST_MECHANISM(id);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, dig_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestUpdate with a NULL session handle\n");
	ret = pfunc->C_DigestUpdate(0, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Call C_DigestUpdate with a NULL data pointer\n");
	ret = pfunc->C_DigestUpdate(sess, NULL_PTR, TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestUpdate with zero-length data\n");
	ret = pfunc->C_DigestUpdate(sess, (CK_BYTE_PTR)TV_MSG(id), 0);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestKey with a NULL session handle\n");
	ret = pfunc->C_DigestKey(0, key);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DigestKey"))
		goto end;

	TEST_OUT("Call C_DigestKey with a NULL key handle\n");
	ret = pfunc->C_DigestKey(sess, key);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_DigestKey"))
		goto end;

	TEST_OUT("Create RSA Key Public\n");
	ret = pfunc->C_CreateObject(sess, public_key_template,
				    ARRAY_SIZE(public_key_template),
				    &rsa_pub_key);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Call C_DigestKey with an indigestible (non-secret) key\n");
	ret = pfunc->C_DigestKey(sess, rsa_pub_key);
	if (CHECK_CK_RV(CKR_KEY_INDIGESTIBLE, "C_DigestKey"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs), &aes_key);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Call C_DigestKey with a sensitive & un-extractable key\n");
	ret = pfunc->C_DigestKey(sess, aes_key);
	if (CHECK_CK_RV(CKR_KEY_INDIGESTIBLE, "C_DigestKey"))
		goto end;

	TEST_OUT("Call C_DigestFinal with a NULL session handle\n");
	ret = pfunc->C_DigestFinal(0, digest, &digest_length);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DigestFinal"))
		goto end;

	TEST_OUT("Call C_DigestFinal with NULL digest length pointer\n");
	ret = pfunc->C_DigestFinal(sess, digest, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DigestFinal"))
		goto end;

	status = TEST_PASS;

end:
	if (rsa_pub_key) {
		TEST_OUT("Destroy RSA public key");
		ret = pfunc->C_DestroyObject(sess, rsa_pub_key);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	if (aes_key) {
		TEST_OUT("Destroy AES key");
		ret = pfunc->C_DestroyObject(sess, aes_key);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int digest_multipart_no_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE digest[32] = { 0 };
	CK_ULONG digest_length = 32;
	enum mechanism_id id = MECH_ID_SHA256;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	TEST_OUT("Call C_DigestUpdate without prior init\n");
	ret = pfunc->C_DigestUpdate(sess, (CK_BYTE_PTR)TV_MSG(id),
				    TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Digest"))
		goto end;

	TEST_OUT("Call C_DigestFinal without prior init\n");
	ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DigestFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int digest_multipart_wrong_order(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM dig_mech = { 0 };
	CK_BYTE digest[32] = { 0 };
	CK_ULONG digest_length = 32;
	enum mechanism_id id = MECH_ID_SHA256;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	dig_mech.mechanism = DIGEST_MECHANISM(id);

	if (!util_lib_is_mech_supported(pfunc, 0, dig_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Re-initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestUpdate\n");
	ret = pfunc->C_DigestUpdate(sess, (CK_BYTE_PTR)TV_MSG(id),
				    TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Call single-part digest during active multi-part op\n");
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, &digest_length);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Digest"))
		goto end;

	TEST_OUT("Finish multi-part digest operation\n");
	ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Perform single-part digest operation\n");
	ret = pfunc->C_Digest(sess, (CK_BYTE_PTR)TV_MSG(id), TV_MSG_LEN(id),
			      digest, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_Digest"))
		goto end;

	TEST_OUT("Call C_DigestFinal without prior init\n");
	ret = pfunc->C_DigestUpdate(sess, (CK_BYTE_PTR)TV_MSG(id),
				    TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DigestUpdate"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int digest_multipart_cancel_op(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM dig_mech = { 0 };
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	enum mechanism_id id = MECH_ID_SHA256;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	dig_mech.mechanism = DIGEST_MECHANISM(id);

	if (!util_lib_is_mech_supported(pfunc, 0, dig_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	digest_length = DIGEST_LENGTH(id);
	digest = malloc(digest_length);
	if (CHECK_EXPECTED(digest, "Allocation error"))
		goto end;

	TEST_OUT("Call C_DigestUpdate\n");
	ret = pfunc->C_DigestUpdate(sess, (CK_BYTE_PTR)TV_MSG(id),
				    TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Cancel on-going multi-part digest operation\n");
	ret = pfunc->C_DigestInit(sess, NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestFinal without prior init\n");
	ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DigestFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_multipart_get_digest_length(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM dig_mech = { 0 };
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	CK_ULONG temp_digest_len = 0;
	enum mechanism_id id = MECH_ID_SHA256;
	bool match = false;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	dig_mech.mechanism = DIGEST_MECHANISM(id);

	if (!util_lib_is_mech_supported(pfunc, 0, dig_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestUpdate\n");
	ret = pfunc->C_DigestUpdate(sess, (CK_BYTE_PTR)TV_MSG(id),
				    TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Retrieve digest length\n");
	ret = pfunc->C_DigestFinal(sess, NULL_PTR, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	match = check_digest_length(DIGEST_LENGTH(id), digest_length);
	if (CHECK_EXPECTED(match, "Digest length mismatch"))
		goto end;

	digest_length = DIGEST_LENGTH(id);
	if (MUL_OVERFLOW(digest_length, 2, &temp_digest_len))
		goto end;

	digest = malloc(temp_digest_len);
	digest_length >>= 1;
	if (CHECK_EXPECTED(digest, "Allocation error"))
		goto end;

	TEST_OUT("Call C_DigestFinal with digest buffer length too short\n");
	ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_DigestFinal"))
		goto end;

	match = check_digest_length(DIGEST_LENGTH(id), digest_length);
	if (CHECK_EXPECTED(match, "Digest length mismatch"))
		goto end;

	TEST_OUT("Call C_DigestFinal with digest buffer length too long\n");
	digest_length <<= 1;

	ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	match = check_digest(TV_DIGEST(id), DIGEST_LENGTH(id), digest,
			     digest_length);
	if (CHECK_EXPECTED(match, "Digest mismatch"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_multipart_all_mechanisms(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM dig_mech = { 0 };
	CK_BYTE_PTR message = NULL_PTR;
	CK_ULONG total_message_length = 0;
	CK_ULONG message_part_length = 0;
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	unsigned int i = 0;
	bool match = false;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	for (; i < MECH_ID_NB; i++) {
		TEST_OUT("Check digest %s\n", DIGEST_NAME(i));
		dig_mech.mechanism = DIGEST_MECHANISM(i);

		if (!util_lib_is_mech_supported(pfunc, 0, dig_mech.mechanism))
			continue;

		TEST_OUT("Initialize digest operation\n");
		ret = pfunc->C_DigestInit(sess, &dig_mech);
		if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
			goto end;

		digest_length = DIGEST_LENGTH(i);
		digest = malloc(digest_length);
		if (CHECK_EXPECTED(digest, "Allocation error"))
			goto end;

		message = (CK_BYTE_PTR)TV_MSG(i);
		total_message_length = TV_MSG_LEN(i);
		message_part_length = total_message_length / 2;

		TEST_OUT("Call C_DigestUpdate with first part of data\n");
		ret = pfunc->C_DigestUpdate(sess, message, message_part_length);
		if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
			goto end;

		TEST_OUT("Call C_DigestUpdate with second part of data\n");
		ret = pfunc->C_DigestUpdate(sess, message + message_part_length,
					    total_message_length -
						    message_part_length);
		if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
			goto end;

		TEST_OUT("Finalize the multi-part digest operation\n");
		ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
		if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
			goto end;

		match = check_digest(TV_DIGEST(i), DIGEST_LENGTH(i), digest,
				     digest_length);
		if (CHECK_EXPECTED(match, "Digest mismatch"))
			goto end;

		free(digest);
		digest = NULL_PTR;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_multipart_empty_data(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM dig_mech = { 0 };
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	unsigned int i = 0;
	bool match = false;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	for (; i < MECH_ID_NB; i++) {
		TEST_OUT("Check digest %s\n", DIGEST_NAME(i));
		dig_mech.mechanism = DIGEST_MECHANISM(i);

		if (!util_lib_is_mech_supported(pfunc, 0, dig_mech.mechanism))
			continue;

		TEST_OUT("Initialize digest operation\n");
		ret = pfunc->C_DigestInit(sess, &dig_mech);
		if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
			goto end;

		digest_length = 0;
		TEST_OUT("Retrieve digest length for empty data\n");
		ret = pfunc->C_DigestFinal(sess, NULL_PTR, &digest_length);
		if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
			goto end;

		match = check_digest_length(DIGEST_LENGTH(i), digest_length);
		if (CHECK_EXPECTED(match, "Digest length mismatch"))
			goto end;

		digest = malloc(digest_length);
		if (CHECK_EXPECTED(digest, "Allocation error"))
			goto end;

		TEST_OUT("Perform digest operation on empty data\n");
		ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
		if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
			goto end;

		match = check_digest(TV_DIGEST_ND(i), DIGEST_LENGTH(i), digest,
				     digest_length);
		if (CHECK_EXPECTED(match, "Digest mismatch"))
			goto end;

		free(digest);
		digest = NULL_PTR;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

static int digest_multipart_key(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM dig_mech = { 0 };
	CK_BYTE_PTR digest = NULL_PTR;
	CK_ULONG digest_length = 0;
	enum mechanism_id id = MECH_ID_SHA256;
	bool match = false;

	CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG key_length = 32;
	CK_MECHANISM key_gen_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM_TYPE aes_allowed_mech = CKM_AES_ECB;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;
	CK_BYTE key_value[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

	CK_BYTE expected_digest_256[] = { 0x71, 0xf9, 0x5a, 0x5a, 0xfb, 0x75,
					  0x86, 0x46, 0x61, 0x29, 0xee, 0xbd,
					  0xba, 0x04, 0xdc, 0x89, 0x50, 0x28,
					  0x8d, 0x8e, 0x21, 0x7a, 0x2d, 0xd3,
					  0xd2, 0xe1, 0xf7, 0x1f, 0x3c, 0xe1,
					  0xc1, 0x30 };

	CK_OBJECT_HANDLE key_handle = 0;
	CK_OBJECT_HANDLE generated_key_handle = 0;
	CK_ATTRIBUTE aes_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SENSITIVE, &ck_false, sizeof(CK_BBOOL) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_EXTRACTABLE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, &key_value, sizeof(key_value) },
		{ CKA_ALLOWED_MECHANISMS, &aes_allowed_mech,
		  sizeof(aes_allowed_mech) },
	};
	CK_ATTRIBUTE aes_key_generate_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &aes_allowed_mech,
		  sizeof(aes_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Createobject AES ECB secret Key\n");
	ret = pfunc->C_CreateObject(sess, aes_key_attrs,
				    ARRAY_SIZE(aes_key_attrs), &key_handle);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	dig_mech.mechanism = DIGEST_MECHANISM(id);
	if (!util_lib_is_mech_supported(pfunc, 0, dig_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestUpdate\n");
	ret = pfunc->C_DigestUpdate(sess, (CK_BYTE_PTR)TV_MSG(id),
				    TV_MSG_LEN(id));
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Call C_DigestKey to digest the secret key value\n");
	ret = pfunc->C_DigestKey(sess, key_handle);
	if (CHECK_CK_RV(CKR_OK, "C_DigestKey"))
		goto end;

	TEST_OUT("Retrieve the digest buffer length\n");
	ret = pfunc->C_DigestFinal(sess, NULL_PTR, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	TEST_OUT("Returned digest length = %ld\n", digest_length);

	match = check_digest_length(DIGEST_LENGTH(id), digest_length);
	if (CHECK_EXPECTED(match, "Digest length mismatch"))
		goto end;

	digest_length = DIGEST_LENGTH(id);
	digest = malloc(digest_length);

	TEST_OUT("Finalize the multi-part digest operation\n");
	ret = pfunc->C_DigestFinal(sess, digest, &digest_length);
	if (CHECK_CK_RV(CKR_OK, "C_Digest"))
		goto end;

	match = check_digest(expected_digest_256, DIGEST_LENGTH(id), digest,
			     digest_length);
	if (CHECK_EXPECTED(match, "Digest mismatch"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &key_gen_mech, aes_key_generate_attrs,
				   ARRAY_SIZE(aes_key_generate_attrs),
				   &generated_key_handle);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &dig_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("C_DigestKey fails to digest sensitive secret key value.\n");
	ret = pfunc->C_DigestKey(sess, generated_key_handle);
	if (CHECK_CK_RV(CKR_KEY_INDIGESTIBLE, "C_DigestKey"))
		goto end;

	status = TEST_PASS;

end:
	(void)pfunc->C_DigestInit(sess, NULL_PTR);

	if (key_handle) {
		ret = pfunc->C_DestroyObject(sess, key_handle);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	if (generated_key_handle) {
		ret = pfunc->C_DestroyObject(sess, generated_key_handle);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	if (digest)
		free(digest);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_digest_multipart(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (digest_multipart_bad_params(pfunc) != TEST_PASS)
		goto end;

	if (digest_multipart_no_init(pfunc) != TEST_PASS)
		goto end;

	if (digest_multipart_wrong_order(pfunc) != TEST_PASS)
		goto end;

	if (digest_multipart_cancel_op(pfunc) != TEST_PASS)
		goto end;

	if (digest_multipart_get_digest_length(pfunc) != TEST_PASS)
		goto end;

	if (digest_multipart_all_mechanisms(pfunc) != TEST_PASS)
		goto end;

	if (digest_multipart_empty_data(pfunc) != TEST_PASS)
		goto end;

	status = digest_multipart_key(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
