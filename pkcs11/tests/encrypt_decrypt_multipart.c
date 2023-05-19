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
	"Multi-part cipher operations using symmetric crypto algorithms.";

static int encrypt_decrypt_multipart_no_init(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	/* AES - 128 bits key length */
	CK_ULONG key_length = 16;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) }
	};
	CK_OBJECT_HANDLE hsecretkey = 0;

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG data_len = ARRAY_SIZE(data);
	/* Size of the input data part */
	CK_ULONG part_len = 16;
	CK_ULONG encrypted_part_len = part_len;

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

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Encrypt first data part without init\n");
	ret = pfunc->C_EncryptUpdate(sess, &data[0], part_len,
				     &encrypted_data[0], &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Finish multi-part encryption without init\n");
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[encrypted_part_len],
				    &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Decrypt first encrypted data part without init\n");
	ret = pfunc->C_DecryptUpdate(sess, &encrypted_data[0],
				     encrypted_part_len, &recovered_data[0],
				     &part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Finish multi-part decryption without init\n");
	ret = pfunc->C_DecryptFinal(sess, &recovered_data[part_len], &part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DecryptFinal"))
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

static int encrypt_multipart_wrong_order(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	/* AES - 128 bits key length */
	CK_ULONG key_length = 16;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) }
	};
	CK_OBJECT_HANDLE hsecretkey = 0;

	CK_MECHANISM encrypt_decrypt_mech = { .mechanism = CKM_AES_CBC };

	CK_BYTE iv[] = { 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			 0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_ULONG encrypted_data_len = data_len;
	/* Size of the input data part */
	CK_ULONG part_len = 16;
	CK_ULONG encrypted_part_len = part_len;

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

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	encrypt_decrypt_mech.pParameter = iv;
	encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);

	TEST_OUT("Initialize encryption operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Encrypt the first data part\n");
	ret = pfunc->C_EncryptUpdate(sess, &data[0], part_len,
				     &encrypted_data[0], &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Perform single-part encryption intervening multi-part\n");
	ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
			       &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Encrypt"))
		goto end;

	TEST_OUT("Finish multi-part encryption operation\n");
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[encrypted_part_len],
				    &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Initialize encryption operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Perform single-part encryption\n");
	ret = pfunc->C_Encrypt(sess, data, data_len, encrypted_data,
			       &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
		goto end;

	TEST_OUT("Encrypt the first data part without init\n");
	ret = pfunc->C_EncryptUpdate(sess, &data[0], part_len,
				     &encrypted_data[0], &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Finish multi-part encryption operation without init\n");
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[encrypted_part_len],
				    &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_EncryptFinal"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (encrypted_data)
		free(encrypted_data);

	SUBTEST_END(status);
	return status;
}

static int decrypt_multipart_wrong_order(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	/* AES - 128 bits key length */
	CK_ULONG key_length = 16;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) }
	};
	CK_OBJECT_HANDLE hsecretkey = 0;

	CK_MECHANISM encrypt_decrypt_mech = { CKM_AES_ECB, NULL_PTR, 0 };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_ULONG encrypted_data_len = data_len;
	/* Size of the input data part */
	CK_ULONG encrypted_part_len = 16;
	CK_ULONG part_recovered_len = encrypted_part_len;

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

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize decryption operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	TEST_OUT("Decrypt the first part\n");
	ret = pfunc->C_DecryptUpdate(sess, &encrypted_data[0],
				     encrypted_part_len, &recovered_data[0],
				     &part_recovered_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Perform single-part decryption interrupting multi-part\n");
	ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
			       recovered_data, &data_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_Decrypt"))
		goto end;

	TEST_OUT("Finish a multiple-part decryption operation\n");
	ret = pfunc->C_DecryptFinal(sess, &recovered_data[part_recovered_len],
				    &part_recovered_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
		goto end;

	TEST_OUT("Initialize decryption operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	TEST_OUT("Perform single-part decryption\n");
	ret = pfunc->C_Decrypt(sess, encrypted_data, encrypted_data_len,
			       recovered_data, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
		goto end;

	TEST_OUT("Decrypt the first part without init\n");
	ret = pfunc->C_DecryptUpdate(sess, &encrypted_data[0],
				     encrypted_part_len, &recovered_data[0],
				     &part_recovered_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Finish a multiple-part decryption operation without init\n");
	ret = pfunc->C_DecryptFinal(sess, &recovered_data[part_recovered_len],
				    &part_recovered_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DecryptFinal"))
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

static int encrypt_decrypt_multipart_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	/* AES - 128 bits key length */
	CK_ULONG key_length = 16;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) }
	};
	CK_OBJECT_HANDLE hsecretkey = 0;

	CK_MECHANISM encrypt_decrypt_mech = { .mechanism = CKM_AES_CBC };

	CK_BYTE iv[] = { 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			 0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG data_len = ARRAY_SIZE(data);
	/* Size of the input data part */
	CK_ULONG part_len = 16;
	CK_ULONG encrypted_part_len = part_len;

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

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	encrypt_decrypt_mech.pParameter = iv;
	encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);

	TEST_OUT("Initialize multi-part encryption operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Session's handle in NULL\n");
	ret = pfunc->C_EncryptUpdate(0, &data[0], part_len, &encrypted_data[0],
				     &encrypted_part_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Pointer to input data is NULL\n");
	ret = pfunc->C_EncryptUpdate(sess, NULL_PTR, part_len,
				     &encrypted_data[0], &encrypted_part_len);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Input data length is 0\n");
	ret = pfunc->C_EncryptUpdate(sess, &data[0], 0, &encrypted_data[0],
				     &encrypted_part_len);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Pointer to hold the length of encrypted data is NULL\n");
	ret = pfunc->C_EncryptUpdate(sess, &data[0], part_len,
				     &encrypted_data[0], NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Pointer to hold length of last encrypted part is NULL\n");
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[0], NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Initialize multi-part decryption operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	TEST_OUT("Session's handle in NULL\n");
	ret = pfunc->C_DecryptUpdate(0, &encrypted_data[0], encrypted_part_len,
				     &recovered_data[0], &part_len);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Pointer to encrypted data is NULL\n");
	ret = pfunc->C_DecryptUpdate(sess, NULL_PTR, encrypted_part_len,
				     &recovered_data[0], &part_len);
	if (CHECK_CK_RV(CKR_ENCRYPTED_DATA_INVALID, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Length of the encrypted data is 0\n");
	ret = pfunc->C_DecryptUpdate(sess, &encrypted_data[0], 0,
				     &recovered_data[0], &part_len);
	if (CHECK_CK_RV(CKR_ENCRYPTED_DATA_LEN_RANGE, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Pointer to hold the length of recovered data is NULL\n");
	ret = pfunc->C_DecryptUpdate(sess, &encrypted_data[0],
				     encrypted_part_len, &recovered_data[0],
				     NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Pointer to hold the length of last data part is NULL\n");
	ret = pfunc->C_DecryptFinal(sess, &recovered_data[0], NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DecryptFinal"))
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

static int encrypt_decrypt_cancel_op(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_MECHANISM encrypt_decrypt_mech = { CKM_AES_ECB, NULL_PTR, 0 };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_ULONG part_len = 0;
	CK_ULONG encrypted_part_len = 0;
	/* Size of the input data part */
	const CK_ULONG input_data_block_size = 16;

	CK_OBJECT_HANDLE hsecretkey = 0;

	/* AES - 128 bits key length */
	CK_ULONG key_length = 16;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE aes_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) }
	};

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

	TEST_OUT("Generate AES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &aes_key_mech, aes_secretkey_attrs,
				   ARRAY_SIZE(aes_secretkey_attrs),
				   &hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Initialize encryption operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	part_len = input_data_block_size;
	encrypted_part_len = input_data_block_size;

	TEST_OUT("Encrypt the first data part\n");
	ret = pfunc->C_EncryptUpdate(sess, &data[0], part_len,
				     &encrypted_data[0], &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Cancel on-going multi-part encryption operation\n");
	ret = pfunc->C_EncryptInit(sess, NULL, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("C_EncryptUpdate after finishing the operation\n");
	ret = pfunc->C_EncryptUpdate(sess, &data[0], part_len,
				     &encrypted_data[0], &encrypted_part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Initialize decryption operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	encrypted_part_len = input_data_block_size;
	part_len = input_data_block_size;

	TEST_OUT("Decrypt the first encrypted data part\n");
	ret = pfunc->C_DecryptUpdate(sess, &encrypted_data[0],
				     encrypted_part_len, &recovered_data[0],
				     &part_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Cancel on-going multi-part decryption operation\n");
	ret = pfunc->C_DecryptInit(sess, NULL, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	TEST_OUT("C_DecryptUpdate after finishing the operation\n");
	ret = pfunc->C_DecryptUpdate(sess, &encrypted_data[0],
				     encrypted_part_len, &recovered_data[0],
				     &part_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_DecryptUpdate"))
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

static int multipart_cipher_update(CK_FUNCTION_LIST_PTR pfunc,
				   CK_SESSION_HANDLE sess, CK_BYTE_PTR input,
				   CK_BYTE_PTR output,
				   unsigned int update_loop_count,
				   CK_ULONG input_len,
				   CK_ULONG *total_output_len, bool encrypt)
{
	CK_RV ret = CKR_OK;

	unsigned int i = 0;
	CK_ULONG output_len = 0;
	CK_ULONG in_index = 0;
	CK_ULONG out_index = 0;

	for (; i < update_loop_count; i++) {
		output_len = 0;
		TEST_OUT("Get the length of the output data part %x\n", i);
		in_index = i * input_len;
		out_index = *total_output_len;
		if (encrypt) {
			// coverity[uninitialized_use]
			ret = pfunc->C_EncryptUpdate(sess, &input[in_index],
						     input_len, NULL_PTR,
						     &output_len);

		} else {
			// coverity[uninitialized_use]
			ret = pfunc->C_DecryptUpdate(sess, &input[in_index],
						     input_len, NULL_PTR,
						     &output_len);
		}

		if (ret != CKR_OK)
			return ret;

		TEST_OUT("output_part_len = %lx\n", output_len);

		if (output_len == 0)
			continue;

		TEST_OUT("Multi-part cipher operation\n");
		if (encrypt) {
			// coverity[uninitialized_use]
			ret = pfunc->C_EncryptUpdate(sess, &input[in_index],
						     input_len,
						     &output[out_index],
						     &output_len);

		} else {
			// coverity[uninitialized_use]
			ret = pfunc->C_DecryptUpdate(sess, &input[in_index],
						     input_len,
						     &output[out_index],
						     &output_len);
		}

		if (ret != CKR_OK)
			return ret;

		*total_output_len += output_len;
	}

	TEST_OUT("total output len = %lx\n", *total_output_len);
	return ret;
}

static int multipart_cipher_final(CK_FUNCTION_LIST_PTR pfunc,
				  CK_SESSION_HANDLE sess, CK_BYTE_PTR output,
				  CK_ULONG *total_output_len, bool encrypt)
{
	CK_RV ret = CKR_OK;

	CK_ULONG output_part_len = 0;

	TEST_OUT("Get the length of the last output data part\n");

	if (encrypt)
		ret = pfunc->C_EncryptFinal(sess, NULL, &output_part_len);
	else
		ret = pfunc->C_DecryptFinal(sess, NULL, &output_part_len);

	if (ret != CKR_OK)
		return ret;

	TEST_OUT("output_part_len = 0x%lx\n", output_part_len);

	TEST_OUT("Finish multi-part operation\n");

	if (encrypt) {
		ret = pfunc->C_EncryptFinal(sess, &output[*total_output_len],
					    &output_part_len);
	} else {
		ret = pfunc->C_DecryptFinal(sess, &output[*total_output_len],
					    &output_part_len);
	}

	if (ret != CKR_OK)
		return ret;

	*total_output_len += output_part_len;
	TEST_OUT("total output len = 0x%lx\n", *total_output_len);
	return ret;
}

static int encrypt_decrypt_multipart_aes(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_MECHANISM_TYPE aes_mech_type[] = { CKM_AES_ECB, CKM_AES_CBC,
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
		{ CKA_VALUE, &key_value, sizeof(key_value) },
	};

	unsigned int i = 0;

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;

	CK_ULONG total_encrypted_len = 0;
	CK_ULONG total_recovered_len = 0;
	CK_ULONG data_len = ARRAY_SIZE(data);
	/* Size of the input data part */
	CK_ULONG input_data_block_size = 32;

	/* update_loop_count = data_len/input_data_block_size */
	unsigned int update_loop_count = 2;

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
		memset(encrypted_data, 0, data_len);
		memset(recovered_data, 0, data_len);
		encrypt_decrypt_mech.pParameter = NULL_PTR;
		encrypt_decrypt_mech.ulParameterLen = 0;
		encrypt_decrypt_mech.mechanism = aes_mech_type[i];

		if (encrypt_decrypt_mech.mechanism == CKM_AES_XTS) {
			TEST_OUT("Createobject AES secret Key\n");
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

		TEST_OUT("Initialize encryption operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		total_encrypted_len = 0;

		ret = multipart_cipher_update(pfunc, sess, data, encrypted_data,
					      update_loop_count,
					      input_data_block_size,
					      &total_encrypted_len, true);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
			goto end;

		ret = multipart_cipher_final(pfunc, sess, encrypted_data,
					     &total_encrypted_len, true);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
			goto end;

		TEST_OUT("Initialize decryption operation\n");
		ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
					   aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		total_recovered_len = 0;

		ret = multipart_cipher_update(pfunc, sess, encrypted_data,
					      recovered_data, update_loop_count,
					      input_data_block_size,
					      &total_recovered_len, false);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
			goto end;

		ret = multipart_cipher_final(pfunc, sess, recovered_data,
					     &total_recovered_len, false);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
			goto end;

		TEST_OUT("Plaintext data = %s Plaintext data len = 0x%lx\n",
			 data, data_len);
		TEST_OUT("Recovered_data = %s total_recovered_len = 0x%lx\n",
			 recovered_data, total_recovered_len);

		if (!util_compare_buffers(data, data_len, recovered_data,
					  total_recovered_len)) {
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

static int encrypt_decrypt_multipart_des(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_MECHANISM_TYPE des_mech_type[] = { CKM_DES_ECB, CKM_DES_CBC };

	static CK_BYTE iv_des[] = { 0x01, 0x02, 0x03, 0x04,
				    0x05, 0x06, 0x07, 0x08 };

	CK_MECHANISM encrypt_decrypt_mech = { 0 };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG data_len = ARRAY_SIZE(data);
	/* Size of the input data part */
	CK_ULONG input_data_block_size = 32;
	CK_ULONG total_encrypted_len = 0;
	CK_ULONG total_recovered_len = 0;

	CK_OBJECT_HANDLE des_hsecretkey = 0;

	CK_MECHANISM des_key_mech = { .mechanism = CKM_DES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE des_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
	};

	unsigned int update_loop_count = 2;
	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate DES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &des_key_mech, des_secretkey_attrs,
				   ARRAY_SIZE(des_secretkey_attrs),
				   &des_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	encrypted_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	recovered_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	encrypt_decrypt_mech.pParameter = NULL_PTR;
	encrypt_decrypt_mech.ulParameterLen = 0;

	for (; i < ARRAY_SIZE(des_mech_type); i++) {
		encrypt_decrypt_mech.mechanism = des_mech_type[i];

		if (encrypt_decrypt_mech.mechanism == CKM_DES_CBC) {
			encrypt_decrypt_mech.pParameter = iv_des;
			encrypt_decrypt_mech.ulParameterLen =
				ARRAY_SIZE(iv_des);
		}

		memset(encrypted_data, 0, data_len);
		memset(recovered_data, 0, data_len);

		TEST_OUT("Initialize encryption operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   des_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		total_encrypted_len = 0;

		ret = multipart_cipher_update(pfunc, sess, data, encrypted_data,
					      update_loop_count,
					      input_data_block_size,
					      &total_encrypted_len, true);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
			goto end;

		ret = multipart_cipher_final(pfunc, sess, encrypted_data,
					     &total_encrypted_len, true);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
			goto end;

		TEST_OUT("Initialize decrypt operation\n");
		ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
					   des_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		total_recovered_len = 0;

		ret = multipart_cipher_update(pfunc, sess, encrypted_data,
					      recovered_data, update_loop_count,
					      input_data_block_size,
					      &total_recovered_len, false);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
			goto end;

		ret = multipart_cipher_final(pfunc, sess, recovered_data,
					     &total_recovered_len, false);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
			goto end;

		TEST_OUT("Plaintext data = %s Plaintext data len = 0x%lx\n",
			 data, data_len);
		TEST_OUT("Recovered_data = %s total_recovered_len = 0x%lx\n",
			 recovered_data, total_recovered_len);

		if (!util_compare_buffers(data, data_len, recovered_data,
					  total_recovered_len)) {
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

static int encrypt_decrypt_multipart_des3(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;

	CK_MECHANISM_TYPE des3_mech_type[] = { CKM_DES3_ECB, CKM_DES3_CBC };

	static CK_BYTE iv_des3[] = { 0x01, 0x02, 0x03, 0x04,
				     0x05, 0x06, 0x07, 0x08 };

	CK_MECHANISM encrypt_decrypt_mech = { 0 };
	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG data_len = ARRAY_SIZE(data);
	CK_ULONG total_encrypted_len = 0;
	CK_ULONG total_recovered_len = 0;
	/* Size of the input data part */
	CK_ULONG input_data_block_size = 32;

	CK_OBJECT_HANDLE des3_hsecretkey = 0;

	CK_MECHANISM des3_key_mech = { .mechanism = CKM_DES3_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE des_secretkey_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
	};

	unsigned int update_loop_count = 2;
	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate DES secret Key\n");
	ret = pfunc->C_GenerateKey(sess, &des3_key_mech, des_secretkey_attrs,
				   ARRAY_SIZE(des_secretkey_attrs),
				   &des3_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	encrypted_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	recovered_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	for (; i < ARRAY_SIZE(des3_mech_type); i++) {
		encrypt_decrypt_mech.mechanism = des3_mech_type[i];

		if (encrypt_decrypt_mech.mechanism == CKM_DES3_CBC) {
			encrypt_decrypt_mech.pParameter = iv_des3;
			encrypt_decrypt_mech.ulParameterLen =
				ARRAY_SIZE(iv_des3);
		}

		memset(encrypted_data, 0, data_len);
		memset(recovered_data, 0, data_len);

		TEST_OUT("Initialize encryption operation\n");
		ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
					   des3_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
			goto end;

		total_encrypted_len = 0;

		ret = multipart_cipher_update(pfunc, sess, data, encrypted_data,
					      update_loop_count,
					      input_data_block_size,
					      &total_encrypted_len, true);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
			goto end;

		ret = multipart_cipher_final(pfunc, sess, encrypted_data,
					     &total_encrypted_len, true);
		if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
			goto end;

		TEST_OUT("Initialize decryption operation\n");
		ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
					   des3_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
			goto end;

		total_recovered_len = 0;
		ret = multipart_cipher_update(pfunc, sess, encrypted_data,
					      recovered_data, update_loop_count,
					      input_data_block_size,
					      &total_recovered_len, false);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
			goto end;

		ret = multipart_cipher_final(pfunc, sess, recovered_data,
					     &total_recovered_len, false);
		if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
			goto end;

		TEST_OUT("Plaintext data = %s Plaintext data len = 0x%lx\n",
			 data, data_len);
		TEST_OUT("Recovered_data = %s total_recovered_len = 0x%lx\n",
			 recovered_data, total_recovered_len);

		if (!util_compare_buffers(data, data_len, recovered_data,
					  total_recovered_len)) {
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

void tests_pkcs11_encrypt_decrypt_multipart(void *lib_hdl,
					    CK_FUNCTION_LIST_PTR pfunc)
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

	if (encrypt_decrypt_multipart_no_init(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_multipart_wrong_order(pfunc) == TEST_FAIL)
		goto end;

	if (decrypt_multipart_wrong_order(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_multipart_bad_param(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_cancel_op(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_multipart_aes(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_multipart_des(pfunc) == TEST_FAIL)
		goto end;

	if (encrypt_decrypt_multipart_des3(pfunc) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	ret = pfunc->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
