// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_session.h"

#include "util.h"

static CK_BYTE data[] =
	"message to encrypt using symmetric crypto algo (AES, DES, 3DES)";

static int encrypt_init_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM encrypt_mech = { 0 };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	/* AES - 256 bits key length */
	CK_ULONG key_length = 32;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_EncryptInit(0, &encrypt_mech, 0);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_EncryptInit"))
		goto end;

	TEST_OUT("Check key handle NULL\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_mech, 0);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_EncryptInit"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	encrypt_mech.mechanism = CKM_ECDSA;
	ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_EncryptInit"))
		goto end;

	TEST_OUT("Wrong CKM_AES_CTR mechanism parameters:\n");
	encrypt_mech.mechanism = CKM_AES_CTR;
	encrypt_mech.pParameter = NULL;
	encrypt_mech.ulParameterLen = 0;
	ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_EncryptInit"))
		goto end;

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

	CK_OBJECT_HANDLE secret_key_handle = 0;
	/* AES - 192 bits key length */
	CK_ULONG key_length = 24;
	CK_MECHANISM key_gen_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &key_gen_mech, secretkey_attrs,
				   ARRAY_SIZE(secretkey_attrs),
				   &secret_key_handle);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_DecryptInit(0, &decrypt_mech, 0);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DecryptInit"))
		goto end;

	TEST_OUT("Check session and key handle are NULL\n");
	ret = pfunc->C_DecryptInit(sess, &decrypt_mech, 0);
	if (CHECK_CK_RV(CKR_KEY_HANDLE_INVALID, "C_DecryptInit"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");
	decrypt_mech.mechanism = CKM_ECDSA;
	ret = pfunc->C_DecryptInit(sess, &decrypt_mech, secret_key_handle);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_DecryptInit"))
		goto end;

	TEST_OUT("Check bad mechanism parameters:\n");
	decrypt_mech.mechanism = CKM_AES_CBC;
	decrypt_mech.pParameter = NULL;
	decrypt_mech.ulParameterLen = 0;
	ret = pfunc->C_DecryptInit(sess, &decrypt_mech, secret_key_handle);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DecryptInit"))
		goto end;

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
	CK_MECHANISM encrypt_mech = { CKM_AES_ECB, NULL_PTR, 0 };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	/* AES - 256 bits key length */
	CK_ULONG key_length = 32;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
	};

	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_ULONG cipher_len = 0;
	CK_BYTE_PTR cipher = NULL_PTR;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize encryption operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	ret = pfunc->C_Encrypt(sess, data, data_len, NULL_PTR, &cipher_len);
	if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
		goto end;

	cipher = (CK_BYTE_PTR)calloc(cipher_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(cipher, "Allocation error"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_Encrypt(0, data, data_len, cipher, &cipher_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Encrypt"))
		goto end;

	TEST_OUT("Check encrypted data length pointer NULL\n");
	ret = pfunc->C_Encrypt(sess, data, data_len, cipher, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Encrypt"))
		goto end;

	TEST_OUT("Check data pointer NULL\n");
	ret = pfunc->C_Encrypt(sess, NULL_PTR, data_len, cipher, &cipher_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Encrypt"))
		goto end;

	TEST_OUT("Check data length 0\n");
	ret = pfunc->C_Encrypt(sess, data, 0, cipher, &cipher_len);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Encrypt"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (cipher)
		free(cipher);

	SUBTEST_END(status);
	return status;
}

static int decrypt_bad_params(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM decrypt_mech = { CKM_AES_ECB, NULL_PTR, 0 };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	/* AES - 256 bits key length */
	CK_ULONG key_length = 32;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
	};

	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_ULONG plaintext_len = 0;
	CK_BYTE_PTR plaintext = NULL_PTR;
	CK_BYTE_PTR cipher = NULL_PTR;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize decryption operation\n");
	ret = pfunc->C_DecryptInit(sess, &decrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	cipher = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(cipher, "Allocation error"))
		goto end;

	ret = pfunc->C_Decrypt(sess, cipher, data_len, NULL_PTR,
			       &plaintext_len);
	if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
		goto end;

	plaintext = (CK_BYTE_PTR)calloc(plaintext_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(plaintext, "Allocation error"))
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_Decrypt(0, cipher, data_len, plaintext, &plaintext_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_Decrypt"))
		goto end;

	TEST_OUT("Check plaintext length 0\n");
	ret = pfunc->C_Decrypt(sess, cipher, data_len, plaintext, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_Decrypt"))
		goto end;

	TEST_OUT("Check encrypted data pointer NULL\n");
	ret = pfunc->C_Decrypt(sess, NULL_PTR, data_len, plaintext,
			       &plaintext_len);
	if (CHECK_CK_RV(CKR_ENCRYPTED_DATA_INVALID, "C_Decrypt"))
		goto end;

	TEST_OUT("Check encrypted data length 0\n");
	ret = pfunc->C_Decrypt(sess, cipher, 0, plaintext, &plaintext_len);
	if (CHECK_CK_RV(CKR_ENCRYPTED_DATA_LEN_RANGE, "C_Decrypt"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (cipher)
		free(cipher);

	if (plaintext)
		free(plaintext);

	SUBTEST_END(status);
	return status;
}

static int encrypt_decrypt_no_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG cipher_len = 10;
	CK_ULONG data_len = 10;
	CK_BYTE data[data_len];
	CK_BYTE cipher[cipher_len];

	memset(data, 0, data_len * sizeof(CK_BYTE));
	memset(cipher, 0, cipher_len * sizeof(CK_BYTE));

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Encrypt init with NULL mechanism");
	ret = pfunc->C_EncryptInit(sess, NULL_PTR, 1);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Decrypt init with NULL mechanism");
	ret = pfunc->C_DecryptInit(sess, NULL_PTR, 1);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	TEST_OUT("Encrypt without init\n");
	ret = pfunc->C_Encrypt(sess, data, data_len, cipher, &cipher_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Encrypt"))
		goto end;

	TEST_OUT("Decrypt without init\n");
	ret = pfunc->C_Decrypt(sess, cipher, cipher_len, data, &data_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Decrypt"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int encrypt_decrypt_multiple_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM encrypt_decrypt_mech = { .mechanism = CKM_AES_CBC };

	CK_BYTE iv[] = { 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			 0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_AES_KEY_GEN };
	/* AES - 192 bits key length */
	CK_ULONG key_length = 24;

	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	ret = pfunc->C_GenerateKey(sess, &key_mech, secretkey_attrs,
				   ARRAY_SIZE(secretkey_attrs),
				   &aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	encrypt_decrypt_mech.pParameter = iv;
	encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Check multiple encrypt init with same mechanism\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_EncryptInit"))
		goto end;

	TEST_OUT("Check multiple encrypt init with different mechanism\n");
	encrypt_decrypt_mech.mechanism = CKM_AES_ECB;
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_EncryptInit"))
		goto end;

	TEST_OUT("Initialize Decrypt operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	TEST_OUT("Check multiple decrypt init with same mechanism\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_DecryptInit"))
		goto end;

	TEST_OUT("Check multiple decrypt init with different mechanism\n");
	encrypt_decrypt_mech.mechanism = CKM_AES_CBC;
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OPERATION_ACTIVE, "C_DecryptInit"))
		goto end;

	TEST_OUT("Check multiple encrypt init with NULL mechanism\n");
	ret = pfunc->C_EncryptInit(sess, NULL_PTR, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Check multiple decrypt init with NULL mechanism\n");
	ret = pfunc->C_DecryptInit(sess, NULL_PTR, aes_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int encrypt_decrypt_aes(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_MECHANISM_TYPE aes_mech_type[] = { CKM_AES_CBC, CKM_AES_ECB,
					      CKM_AES_CTR, CKM_AES_CTS,
					      CKM_AES_XTS };

	CK_BYTE iv[] = { 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			 0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	/* CK_AES_CTR_PARAMS */
	static const CK_BYTE counter_block[] = { 0x00, 0x01, 0x02, 0x03,
						 0x04, 0x05, 0x06, 0x07,
						 0x00, 0x00, 0x00, 0x00,
						 0x00, 0x00, 0x00, 0x00 };
	const CK_ULONG counter_bits = 64;

	CK_MECHANISM encrypt_decrypt_mech = { 0 };
	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;

	CK_AES_CTR_PARAMS ctr_params = { 0 };
	CK_OBJECT_HANDLE aes_hsecretkey = 0;

	CK_BYTE key_value[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

	CK_KEY_TYPE keyType = CKK_AES;

	/* AES - 256 bits key length */
	CK_ULONG key_length = 32;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;

	CK_ATTRIBUTE aes_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) }
	};

	CK_ATTRIBUTE xts_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &ck_false, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, &key_value, sizeof(key_value) }
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	encrypted_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	recovered_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	for (; i < ARRAY_SIZE(aes_mech_type); i++) {
		encrypt_decrypt_mech.pParameter = NULL_PTR;
		encrypt_decrypt_mech.ulParameterLen = 0;
		encrypt_decrypt_mech.mechanism = aes_mech_type[i];

		if (encrypt_decrypt_mech.mechanism == CKM_AES_XTS) {
			TEST_OUT("Createobject AES XTS secret Key\n");
			ret = pfunc->C_CreateObject(sess, xts_key_attrs,
						    ARRAY_SIZE(xts_key_attrs),
						    &aes_hsecretkey);
			if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
				goto end;
		} else {
			TEST_OUT("Generate AES secret Key\n");
			ret = pfunc->C_GenerateKey(sess, &aes_key_mech,
						   aes_key_attrs,
						   ARRAY_SIZE(aes_key_attrs),
						   &aes_hsecretkey);
			if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
				goto end;
		}

		TEST_OUT("Initialize encrypt operation\n");

		switch (encrypt_decrypt_mech.mechanism) {
		case CKM_AES_CBC:
			encrypt_decrypt_mech.pParameter = iv;
			encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
			break;

		case CKM_AES_CTR:
			memcpy(ctr_params.cb, counter_block,
			       ARRAY_SIZE(counter_block));
			ctr_params.ulCounterBits = counter_bits;
			encrypt_decrypt_mech.pParameter = &ctr_params;
			encrypt_decrypt_mech.ulParameterLen =
				sizeof(ctr_params);
			break;

		case CKM_AES_CTS:
			encrypt_decrypt_mech.pParameter = iv;
			encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
			break;

		case CKM_AES_XTS:
			encrypt_decrypt_mech.pParameter = iv;
			encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
			break;

		default:
			break;
		}

		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		/* Set a wrong encrypted data length */
		encrypted_data_len = 2;

		/* Encrypt message when encrypted data buffer too small */
		ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Encrypt"))
			goto end;

		TEST_OUT("Encrypt message\n");
		ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       NULL_PTR, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		TEST_OUT("Decrypt encrypted data\n");
		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       recovered_data, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		TEST_OUT("Recovered_data = %s recovered_data_len = 0x%lx\n",
			 recovered_data, recovered_data_len);

		if (!util_compare_buffers(data, data_len, recovered_data,
					  recovered_data_len)) {
			TEST_OUT("Decrypted data and plaintext are not same\n");
			goto end;
		}
	}

	status = TEST_PASS;

end:

	util_close_session(pfunc, &sess);

	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	SUBTEST_END(status);
	return status;
}

static int encrypt_decrypt_des(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_MECHANISM_TYPE des_mech_type[] = { CKM_DES_CBC, CKM_DES_ECB };

	static CK_BYTE iv_des[] = { 0x01, 0x02, 0x03, 0x04,
				    0x05, 0x06, 0x07, 0x08 };

	CK_MECHANISM encrypt_decrypt_mech = { 0 };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;

	CK_OBJECT_HANDLE des_hsecretkey = 0;

	CK_MECHANISM aes_key_mech = { .mechanism = CKM_DES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate DES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &des_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	encrypted_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	recovered_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	TEST_OUT("Initialize encrypt operation\n");

	for (; i < ARRAY_SIZE(des_mech_type); i++) {
		TEST_OUT("DES Encryption mechanism = 0x%lx\n",
			 des_mech_type[i]);
		encrypt_decrypt_mech.mechanism = des_mech_type[i];

		if (encrypt_decrypt_mech.mechanism == CKM_DES_CBC) {
			encrypt_decrypt_mech.pParameter = iv_des;
			encrypt_decrypt_mech.ulParameterLen =
				ARRAY_SIZE(iv_des);
		}

		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   des_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		/* Set a wrong encrypted data length */
		encrypted_data_len = 2;

		/* Encrypt message when encrypted data buffer too small */
		ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Encrypt"))
			goto end;

		TEST_OUT("Encrypt message\n");
		ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
					   des_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       NULL_PTR, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		TEST_OUT("Decrypt encrypted data\n");
		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       recovered_data, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		TEST_OUT("Recovered_data = %s recovered_data_len = 0x%lx\n",
			 recovered_data, recovered_data_len);

		if (!util_compare_buffers(data, data_len, recovered_data,
					  recovered_data_len)) {
			TEST_OUT("Decrypted data and plaintext are not same\n");
			goto end;
		}
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	SUBTEST_END(status);
	return status;
}

static int encrypt_decrypt_des3(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM encrypt_decrypt_mech = { 0 };
	CK_MECHANISM_TYPE des3_mech_type[] = { CKM_DES3_CBC, CKM_DES3_ECB };

	static CK_BYTE iv_des3[] = { 0x05, 0x08, 0x03, 0x04,
				     0x09, 0x0A, 0x07, 0x08 };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_ULONG recovered_data_len = 0;
	CK_BYTE_PTR recovered_data = NULL_PTR;

	CK_OBJECT_HANDLE des3_hsecretkey = 0;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_DES3_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
	};

	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate 3DES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &des3_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	encrypted_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	recovered_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	TEST_OUT("Initialize encrypt operation\n");

	for (; i < ARRAY_SIZE(des3_mech_type); i++) {
		TEST_OUT("3DES Encryption mechanism = 0x%lx\n",
			 des3_mech_type[i]);
		encrypt_decrypt_mech.mechanism = des3_mech_type[i];

		if (encrypt_decrypt_mech.mechanism == CKM_DES3_CBC) {
			encrypt_decrypt_mech.pParameter = iv_des3;
			encrypt_decrypt_mech.ulParameterLen =
				ARRAY_SIZE(iv_des3);
		}

		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   des3_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		/* Set a wrong encrypted data length */
		encrypted_data_len = 2;

		/* Encrypt message when encrypted data buffer too small */
		ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Encrypt"))
			goto end;

		TEST_OUT("data_len = 0x%lx, encrypted_data_len = 0x%lx",
			 data_len, encrypted_data_len);

		TEST_OUT("Encrypt message\n");
		ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
				       &encrypted_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
			goto end;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
					   des3_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       NULL_PTR, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		TEST_OUT("Decrypt encrypted data\n");
		ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
				       recovered_data, &recovered_data_len);
		if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
			goto end;

		TEST_OUT("Recovered_data = %s recovered_data_len = 0x%lx\n",
			 recovered_data, recovered_data_len);

		if (!util_compare_buffers(data, data_len, recovered_data,
					  recovered_data_len)) {
			TEST_OUT("Decrypted data and plaintext are not same\n");
			goto end;
		}
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	SUBTEST_END(status);
	return status;
}

static int encrypt_decrypt_key_usage(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM encrypt_decrypt_mech = { .mechanism = CKM_AES_ECB };

	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_ULONG recovered_data_len = 0;

	CK_OBJECT_HANDLE hsecretkey_encrypt = 0;
	CK_OBJECT_HANDLE hsecretkey_decrypt = 0;

	/* AES - 192 bits key length */
	CK_ULONG key_length = 24;
	CK_MECHANISM key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL encrypt = CK_TRUE;
	CK_BBOOL decrypt = CK_FALSE;

	CK_ATTRIBUTE secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &encrypt, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &decrypt, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate AES secret key with CKA_ENCRYPT attribute set\n");
	ret = pfunc->C_GenerateKey(sess, &key_mech, secretkey_attrs,
				   ARRAY_SIZE(secretkey_attrs),
				   &hsecretkey_encrypt);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Generate AES secret key with CKA_DECRYPT attribute set\n");
	encrypt = CK_FALSE;
	decrypt = CK_TRUE;
	ret = pfunc->C_GenerateKey(sess, &key_mech, secretkey_attrs,
				   ARRAY_SIZE(secretkey_attrs),
				   &hsecretkey_decrypt);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize encrypt operation with decrypt secret key\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
				   hsecretkey_decrypt);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_EncryptInit"))
		goto end;

	TEST_OUT("Initialize encrypt operation with encrypt secret key\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
				   hsecretkey_encrypt);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	ret = pfunc->C_Encrypt(sess, data, data_len, NULL_PTR,
			       &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
		goto end;

	encrypted_data =
		(CK_BYTE_PTR)calloc(encrypted_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	TEST_OUT("Encrypt message\n");
	ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
			       &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
		goto end;

	TEST_OUT("Initialize decrypt operation with non decrypt key\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
				   hsecretkey_encrypt);
	if (CHECK_CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED, "C_DecryptInit"))
		goto end;

	TEST_OUT("Initialize decrypt operation with correct decrypt key\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
				   hsecretkey_decrypt);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
			       NULL_PTR, &recovered_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
		goto end;

	recovered_data =
		(CK_BYTE_PTR)calloc(recovered_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	TEST_OUT("Decrypt encrypted data\n");
	ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
			       recovered_data, &recovered_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_encrypt_decrypt(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
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

	if (encrypt_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (decrypt_init_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (decrypt_bad_params(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_no_init(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_multiple_init(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_aes(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_des3(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_des(pfunc) == TEST_FAIL)
		goto end;

	status = encrypt_decrypt_key_usage(pfunc);

end:
	ret = pfunc->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
