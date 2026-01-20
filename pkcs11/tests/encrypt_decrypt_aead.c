// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2026 NXP
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os_mutex.h"
#include "util_session.h"

#include "util.h"

static CK_BYTE data[] =
	"message to encrypt using authenticated encryption (CCM, GCM, POLY1305)";

static CK_BYTE aad[] = "additional data used for authenticated encryption";

static CK_BYTE iv[] = { 0x01, 0x02, 0x03, 0x04,	 0x05, 0x06,
			0x07, 0x08, 0x09, 0x010, 0x0A, 0x0B };

#define ATTRIBUTE(_class, _value)                                              \
	{                                                                      \
		.type = _class, .pValue = &(_value),                           \
		.ulValueLen = sizeof(_value)                                   \
	}

#define MECH_DATA(_mech)                                                       \
	{                                                                      \
		.mech_type = CKM_##_mech, .optional = CK_FALSE,                \
		.key_attrs = { ATTRIBUTE(CKA_CLASS, secret_key_class),         \
			       ATTRIBUTE(CKA_ENCRYPT, ck_true),                \
			       ATTRIBUTE(CKA_DECRYPT, ck_true),                \
			       ATTRIBUTE(CKA_VALUE_LEN, key_length),           \
			       ATTRIBUTE(CKA_ALLOWED_MECHANISMS,               \
					 key_allowed_mech_##_mech) },          \
		.good_params_ptr = &params_##_mech,                            \
		.good_params_len = sizeof(params_##_mech)                      \
	}

#define MECH_DATA_OPT(_mech)                                                   \
	{                                                                      \
		.mech_type = CKM_##_mech, .optional = CK_TRUE,                 \
		.key_attrs = { ATTRIBUTE(CKA_CLASS, secret_key_class),         \
			       ATTRIBUTE(CKA_ENCRYPT, ck_true),                \
			       ATTRIBUTE(CKA_DECRYPT, ck_true),                \
			       ATTRIBUTE(CKA_VALUE_LEN, key_length),           \
			       ATTRIBUTE(CKA_ALLOWED_MECHANISMS,               \
					 key_allowed_mech_##_mech) },          \
		.good_params_ptr = &params_##_mech,                            \
		.good_params_len = sizeof(params_##_mech)                      \
	}

static CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
static CK_BBOOL ck_true = CK_TRUE;
static CK_ULONG key_length = 32;
static CK_MECHANISM_TYPE key_allowed_mech_AES_CCM[] = { CKM_AES_CCM };
static CK_MECHANISM_TYPE key_allowed_mech_AES_GCM[] = { CKM_AES_GCM };
static CK_MECHANISM_TYPE key_allowed_mech_CHACHA20_POLY1305[] = {
	CKM_CHACHA20_POLY1305
};

static CK_CCM_PARAMS params_AES_CCM = { .pAAD = aad,
					.ulAADLen = sizeof(aad),
					.pNonce = iv,
					.ulNonceLen = sizeof(iv),
					.ulDataLen = sizeof(data),
					.ulMACLen = 16 };

static CK_GCM_PARAMS params_AES_GCM = { .pAAD = aad,
					.ulAADLen = sizeof(aad),
					.pIv = iv,
					.ulIvLen = sizeof(iv),
					.ulTagBits = BYTES_TO_BITS(16) };

static CK_SALSA20_CHACHA20_POLY1305_PARAMS params_CHACHA20_POLY1305 = {
	.pAAD = aad,
	.ulAADLen = sizeof(aad),
	.pNonce = iv,
	.ulNonceLen = sizeof(iv)
};

static struct {
	CK_MECHANISM_TYPE mech_type;
	CK_BBOOL optional;
	CK_ATTRIBUTE key_attrs[5];
	CK_RC5_PARAMS bad_params;
	CK_VOID_PTR good_params_ptr;
	CK_ULONG good_params_len;
} aead_mech[] = { MECH_DATA(AES_CCM), MECH_DATA_OPT(AES_GCM),
		  MECH_DATA_OPT(CHACHA20_POLY1305) };

static int encrypt_init_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM encrypt_mech = { 0 };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };

	size_t i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(aead_mech); i++) {
		TEST_OUT("Generate AES secret Key\n");
		ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
					   aead_mech[i].key_attrs,
					   ARRAY_SIZE(aead_mech[i].key_attrs),
					   &aes_hsecretkey);
		if (ret == CKR_MECHANISM_INVALID && aead_mech[i].optional) {
			TEST_OUT("Mechanism 0x%lx not supported!\n",
				 aead_mech[i].mech_type);
			continue;
		} else if (CHECK_CK_RV(CKR_OK, "C_GenerateKey")) {
			goto end;
		}

		TEST_OUT("Check session NULL\n");
		ret = pfunc->C_EncryptInit(0, &encrypt_mech, 0);
		if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_EncryptInit"))
			goto end;

		TEST_OUT("Check key handle NULL\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_mech, 0);
		if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_EncryptInit"))
			goto end;

		encrypt_mech.mechanism = aead_mech[i].mech_type;

		TEST_OUT("Wrong AEAD parameter: NULL\n");
		encrypt_mech.pParameter = NULL_PTR;
		encrypt_mech.ulParameterLen = 0;
		ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_EncryptInit"))
			goto end;

		TEST_OUT("Wrong AEAD parameter struct\n");
		encrypt_mech.pParameter = &aead_mech[i].bad_params;
		encrypt_mech.ulParameterLen = sizeof(aead_mech[i].bad_params);
		ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_EncryptInit"))
			goto end;

		ret = pfunc->C_DestroyObject(sess, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		aes_hsecretkey = 0;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int decrypt_init_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM decrypt_mech = { 0 };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };

	size_t i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(aead_mech); i++) {
		TEST_OUT("Generate AES secret Key\n");
		ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
					   aead_mech[i].key_attrs,
					   ARRAY_SIZE(aead_mech[i].key_attrs),
					   &aes_hsecretkey);
		if (ret == CKR_MECHANISM_INVALID && aead_mech[i].optional) {
			TEST_OUT("Mechanism 0x%lx not supported!\n",
				 aead_mech[i].mech_type);
			continue;
		} else if (CHECK_CK_RV(CKR_OK, "C_GenerateKey")) {
			goto end;
		}

		TEST_OUT("Check session NULL\n");
		ret = pfunc->C_DecryptInit(0, &decrypt_mech, 0);
		if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DecryptInit"))
			goto end;

		TEST_OUT("Check key handle NULL\n");
		ret = pfunc->C_DecryptInit(sess, &decrypt_mech, 0);
		if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_DecryptInit"))
			goto end;

		decrypt_mech.mechanism = aead_mech[i].mech_type;

		TEST_OUT("Wrong AEAD parameter: NULL\n");
		decrypt_mech.pParameter = NULL_PTR;
		decrypt_mech.ulParameterLen = 0;
		ret = pfunc->C_DecryptInit(sess, &decrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_EncryptInit"))
			goto end;

		TEST_OUT("Wrong AEAD parameter struct\n");
		decrypt_mech.pParameter = &aead_mech[i].bad_params;
		decrypt_mech.ulParameterLen = sizeof(aead_mech[i].bad_params);
		ret = pfunc->C_DecryptInit(sess, &decrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DecryptInit"))
			goto end;

		ret = pfunc->C_DestroyObject(sess, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		aes_hsecretkey = 0;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int encrypt_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	size_t i = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM encrypt_mech = { 0 };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(aead_mech); i++) {
		TEST_OUT("Generate AES secret Key\n");
		ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
					   aead_mech[i].key_attrs,
					   ARRAY_SIZE(aead_mech[i].key_attrs),
					   &aes_hsecretkey);
		if (ret == CKR_MECHANISM_INVALID && aead_mech[i].optional) {
			TEST_OUT("Mechanism 0x%lx not supported!\n",
				 aead_mech[i].mech_type);
			continue;
		} else if (CHECK_CK_RV(CKR_OK, "C_GenerateKey")) {
			goto end;
		}

		encrypt_mech.mechanism = aead_mech[i].mech_type;
		encrypt_mech.pParameter = aead_mech[i].good_params_ptr;
		encrypt_mech.ulParameterLen = aead_mech[i].good_params_len;

		TEST_OUT("Initialize encrypt operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		TEST_OUT("Check valid session\n");
		ret = pfunc->C_Encrypt(0, data, sizeof(data), NULL_PTR,
				       NULL_PTR);
		if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Encrypt"))
			goto end;

		TEST_OUT("Check output length NULL\n");
		ret = pfunc->C_Encrypt(sess, data, sizeof(data), NULL_PTR,
				       NULL_PTR);
		if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize encrypt operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		encrypted_data_len = 0;
		ret = pfunc->C_Encrypt(sess, data, sizeof(data), NULL_PTR,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
			goto end;

		encrypted_data = (CK_BYTE_PTR)calloc(encrypted_data_len,
						     sizeof(CK_BYTE));
		if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
			goto end;

		TEST_OUT("Check session NULL\n");
		ret = pfunc->C_Encrypt(0, NULL_PTR, 0, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Encrypt"))
			goto end;

		TEST_OUT("Check data length 0\n");
		ret = pfunc->C_Encrypt(sess, data, 0, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize encrypt operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		TEST_OUT("Check data NULL\n");
		ret = pfunc->C_Encrypt(sess, NULL_PTR, sizeof(data),
				       encrypted_data, &encrypted_data_len);
		if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Encrypt"))
			goto end;

		free(encrypted_data);
		encrypted_data = NULL_PTR;

		ret = pfunc->C_DestroyObject(sess, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		aes_hsecretkey = 0;
	}

	status = TEST_PASS;

end:
	if (encrypted_data)
		free(encrypted_data);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int decrypt_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	size_t i = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM decrypt_mech = { 0 };

	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(aead_mech); i++) {
		TEST_OUT("Generate AES secret Key\n");
		ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
					   aead_mech[i].key_attrs,
					   ARRAY_SIZE(aead_mech[i].key_attrs),
					   &aes_hsecretkey);
		if (ret == CKR_MECHANISM_INVALID && aead_mech[i].optional) {
			TEST_OUT("Mechanism 0x%lx not supported!\n",
				 aead_mech[i].mech_type);
			continue;
		} else if (CHECK_CK_RV(CKR_OK, "C_GenerateKey")) {
			goto end;
		}

		decrypt_mech.mechanism = aead_mech[i].mech_type;
		decrypt_mech.pParameter = aead_mech[i].good_params_ptr;
		decrypt_mech.ulParameterLen = aead_mech[i].good_params_len;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &decrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		TEST_OUT("Check valid session\n");
		ret = pfunc->C_Decrypt(0, data, sizeof(data), NULL_PTR,
				       NULL_PTR);
		if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Decrypt"))
			goto end;

		TEST_OUT("Check output length NULL\n");
		ret = pfunc->C_Decrypt(sess, data, sizeof(data), NULL_PTR,
				       NULL_PTR);
		if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Decrypt"))
			goto end;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &decrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		recovered_data_len = 0;
		ret = pfunc->C_Decrypt(sess, data, sizeof(data), NULL_PTR,
				       &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		recovered_data = (CK_BYTE_PTR)calloc(recovered_data_len,
						     sizeof(CK_BYTE));
		if (CHECK_EXPECTED(recovered_data, "Allocation error"))
			goto end;

		TEST_OUT("Check session NULL\n");
		ret = pfunc->C_Decrypt(0, NULL_PTR, 0, recovered_data,
				       &recovered_data_len);
		if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Decrypt"))
			goto end;

		TEST_OUT("Check data length 0\n");
		ret = pfunc->C_Decrypt(sess, data, 0, recovered_data,
				       &recovered_data_len);
		if (CHECK_CK_RV(CKR_ENCRYPTED_DATA_LEN_RANGE, "C_Decrypt"))
			goto end;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &decrypt_mech, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		TEST_OUT("Check data NULL\n");
		ret = pfunc->C_Decrypt(sess, NULL_PTR, sizeof(data),
				       recovered_data, &recovered_data_len);
		if (CHECK_CK_RV(CKR_ENCRYPTED_DATA_INVALID, "C_Decrypt"))
			goto end;

		free(recovered_data);
		recovered_data = NULL_PTR;

		ret = pfunc->C_DestroyObject(sess, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		aes_hsecretkey = 0;
	}

	status = TEST_PASS;

end:
	if (recovered_data)
		free(recovered_data);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int encrypt_decrypt_aead(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	size_t i = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_MECHANISM encrypt_decrypt_mech = { 0 };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;
	CK_ULONG tmp = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(aead_mech); i++) {
		TEST_OUT("Generate AES secret Key\n");
		ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
					   aead_mech[i].key_attrs,
					   ARRAY_SIZE(aead_mech[i].key_attrs),
					   &aes_hsecretkey);
		if (ret == CKR_MECHANISM_INVALID && aead_mech[i].optional) {
			TEST_OUT("Mechanism 0x%lx not supported!\n",
				 aead_mech[i].mech_type);
			continue;
		} else if (CHECK_CK_RV(CKR_OK, "C_GenerateKey")) {
			goto end;
		}

		encrypt_decrypt_mech.mechanism = aead_mech[i].mech_type;
		encrypt_decrypt_mech.pParameter = aead_mech[i].good_params_ptr;
		encrypt_decrypt_mech.ulParameterLen =
			aead_mech[i].good_params_len;

		TEST_OUT("Initialize encrypt operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		TEST_OUT("Get output buffer length, data=NULL and length=0\n");
		ret = pfunc->C_Encrypt(sess, NULL_PTR, 0, NULL_PTR, &tmp);
		if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize encrypt operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		TEST_OUT("Get output buffer length, data_len=0\n");
		ret = pfunc->C_Encrypt(sess, data, 0, NULL_PTR, &tmp);
		if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize encrypt operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		TEST_OUT("Get output buffer length, data=NULL\n");
		ret = pfunc->C_Encrypt(sess, NULL_PTR, sizeof(data), NULL_PTR,
				       &tmp);
		if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize encrypt operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		encrypted_data_len = 0;
		/* Encrypt message when encrypted data buffer too small */
		ret = pfunc->C_Encrypt(sess, data, sizeof(data), NULL_PTR,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
			goto end;

		encrypted_data = (CK_BYTE_PTR)calloc(encrypted_data_len,
						     sizeof(CK_BYTE));
		if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
			goto end;

		TEST_OUT("Encrypt message\n");
		ret = pfunc->C_Encrypt(sess, data, sizeof(data), encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		recovered_data_len = 0;
		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       NULL_PTR, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		recovered_data = (CK_BYTE_PTR)calloc(recovered_data_len,
						     sizeof(CK_BYTE));
		if (CHECK_EXPECTED(recovered_data, "Allocation error"))
			goto end;

		TEST_OUT("Decrypt encrypted data\n");
		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       recovered_data, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		free(encrypted_data);
		encrypted_data = NULL_PTR;

		TEST_DUMP_HEX("Recovered_data", recovered_data,
			      recovered_data_len);

		if (!util_compare_buffers(data, sizeof(data), recovered_data,
					  recovered_data_len)) {
			TEST_OUT("Decrypted data and plaintext are not same\n");
			goto end;
		}

		free(recovered_data);
		recovered_data = NULL_PTR;

		ret = pfunc->C_DestroyObject(sess, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		aes_hsecretkey = 0;
	}

	status = TEST_PASS;

end:
	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_encrypt_decrypt_aead(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (encrypt_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (decrypt_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (decrypt_bad_params(pfunc) == TEST_FAIL)
		goto end;

	status = encrypt_decrypt_aead(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
