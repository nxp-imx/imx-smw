// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"
#include "util.h"
#include "util_digest.h"

#define NB_KEYS_HDL 3

static CK_BYTE data1[] =
	"Multi-part cipher operations using symmetric crypto algorithms (part 1)";
static CK_BYTE data2[] =
	"Multi-part cipher operations using symmetric crypto algorithms (part 2)";
static CK_BYTE data3[] =
	"Multi-part cipher operations using symmetric crypto algorithms (part 3, final).";

static int operation_state_cipher_encrypt(CK_FUNCTION_LIST_PTR pfunc,
					  CK_SESSION_HANDLE session,
					  CK_MECHANISM_PTR encrypt_mech,
					  CK_OBJECT_HANDLE hsecretkey)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_ULONG encrypted_length = 0;

	CK_BYTE_PTR encrypted_data_1 = NULL_PTR;
	CK_ULONG index_data_1 = 0;

	CK_BYTE_PTR encrypted_data_2 = NULL_PTR;
	CK_ULONG index_data_2 = 0;

	CK_BYTE_PTR operation_state = NULL_PTR;
	CK_ULONG operation_state_len = 0;
	CK_ULONG skip_over = 0;
	CK_ULONG encrypted_data_size = 0;

	encrypted_data_size =
		sizeof(data1) + sizeof(data2) + sizeof(data3) + 64;

	TEST_OUT("Allocate first encrypted data\n");
	encrypted_data_1 = calloc(1, encrypted_data_size);
	if (CHECK_EXPECTED(encrypted_data_1, "Allocation error"))
		goto end;

	TEST_OUT("Allocate second encrypted data\n");
	encrypted_data_2 = calloc(1, encrypted_data_size);
	if (CHECK_EXPECTED(encrypted_data_2, "Allocation error"))
		goto end;

	TEST_OUT("Initialize encryption operation\n");
	ret = pfunc->C_EncryptInit(session, encrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Encrypt data first part\n");
	encrypted_length = encrypted_data_size;
	ret = pfunc->C_EncryptUpdate(session, data1, sizeof(data1),
				     &encrypted_data_1[index_data_1],
				     &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	/*
	 * This ciphertext is only part of encrypted_data_1, because the operation
	 * state is saved after it is computed.
	 */
	skip_over = index_data_1;

	TEST_OUT("Get the size needed to save the operation state\n");
	ret = pfunc->C_GetOperationState(session, NULL_PTR,
					 &operation_state_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetOperationState"))
		goto end;

	TEST_OUT("Allocate the operation state buffer\n");
	operation_state = calloc(1, operation_state_len);
	if (CHECK_EXPECTED(operation_state, "Allocation error"))
		goto end;

	TEST_OUT("Save the operation state\n");
	ret = pfunc->C_GetOperationState(session, operation_state,
					 &operation_state_len);
	if (ret == CKR_STATE_UNSAVEABLE) {
		TEST_OUT("Cannot save the operation state!\n");
		status = TEST_SKIP;
		goto end;
	} else if (CHECK_CK_RV(CKR_OK, "C_GetOperationState")) {
		goto end;
	}

	TEST_OUT("Encrypt data second part\n");
	encrypted_length = encrypted_data_size - index_data_1;
	ret = pfunc->C_EncryptUpdate(session, data2, sizeof(data2),
				     &encrypted_data_1[index_data_1],
				     &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Encrypt data third part\n");
	encrypted_length = encrypted_data_size - index_data_1;
	ret = pfunc->C_EncryptUpdate(session, data3, sizeof(data3),
				     &encrypted_data_1[index_data_1],
				     &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Finish encrypting data\n");
	encrypted_length = encrypted_data_size - index_data_1;
	ret = pfunc->C_EncryptFinal(session, &encrypted_data_1[index_data_1],
				    &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Set the saved operation state\n");
	ret = pfunc->C_SetOperationState(session, operation_state,
					 operation_state_len, CK_INVALID_HANDLE,
					 CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_OK, "C_SetOperationState"))
		goto end;

	TEST_OUT("Encrypt data second part\n");
	encrypted_length = encrypted_data_size - index_data_2;
	ret = pfunc->C_EncryptUpdate(session, data2, sizeof(data2),
				     &encrypted_data_2[index_data_2],
				     &encrypted_length);
	index_data_2 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Encrypt data third part\n");
	encrypted_length = encrypted_data_size - index_data_2;
	ret = pfunc->C_EncryptUpdate(session, data3, sizeof(data3),
				     &encrypted_data_2[index_data_2],
				     &encrypted_length);
	index_data_2 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Finish encrypting data\n");
	encrypted_length = encrypted_data_size - index_data_2;
	ret = pfunc->C_EncryptFinal(session, &encrypted_data_2[index_data_2],
				    &encrypted_length);
	index_data_2 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	if (!util_compare_buffers(encrypted_data_2,
				  encrypted_data_size - skip_over,
				  encrypted_data_1 + skip_over,
				  encrypted_data_size - skip_over)) {
		TEST_OUT("encrypted_data_1 != encrypted_data_2\n");
		goto end;
	}

	status = TEST_PASS;

end:
	if (encrypted_data_1)
		free(encrypted_data_1);

	if (encrypted_data_2)
		free(encrypted_data_2);

	if (operation_state)
		free(operation_state);

	return status;
}

static int operation_state_cipher_decrypt(CK_FUNCTION_LIST_PTR pfunc,
					  CK_SESSION_HANDLE session,
					  CK_MECHANISM_PTR decrypt_mech,
					  CK_OBJECT_HANDLE hsecretkey)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_ULONG decrypted_length = 0;

	CK_BYTE_PTR decrypted_data_1 = NULL_PTR;
	CK_ULONG index_data_1 = 0;

	CK_BYTE_PTR decrypted_data_2 = NULL_PTR;
	CK_ULONG index_data_2 = 0;

	CK_BYTE_PTR operation_state = NULL_PTR;
	CK_ULONG operation_state_len = 0;
	CK_ULONG skip_over = 0;
	CK_ULONG decrypted_data_size = 0;

	decrypted_data_size =
		sizeof(data1) + sizeof(data2) + sizeof(data3) + 64;

	TEST_OUT("Allocate first decrypted data\n");
	decrypted_data_1 = calloc(1, decrypted_data_size);
	if (CHECK_EXPECTED(decrypted_data_1, "Allocation error"))
		goto end;

	TEST_OUT("Allocate second decrypted data\n");
	decrypted_data_2 = calloc(1, decrypted_data_size);
	if (CHECK_EXPECTED(decrypted_data_2, "Allocation error"))
		goto end;

	TEST_OUT("Initialize decryption operation\n");
	ret = pfunc->C_DecryptInit(session, decrypt_mech, hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	TEST_OUT("Decrypt data first part\n");
	decrypted_length = decrypted_data_size;
	ret = pfunc->C_DecryptUpdate(session, data1, sizeof(data1),
				     &decrypted_data_1[index_data_1],
				     &decrypted_length);
	index_data_1 += decrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	/*
	 * This ciphertext is only part of decrypted_data_1, because the operation
	 * state is saved after it is computed.
	 */
	skip_over = index_data_1;

	TEST_OUT("Get the size needed to save the operation state\n");
	ret = pfunc->C_GetOperationState(session, NULL_PTR,
					 &operation_state_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetOperationState"))
		goto end;

	TEST_OUT("Allocate the operation state buffer\n");
	operation_state = calloc(1, operation_state_len);
	if (CHECK_EXPECTED(operation_state, "Allocation error"))
		goto end;

	TEST_OUT("Save the operation state\n");
	ret = pfunc->C_GetOperationState(session, operation_state,
					 &operation_state_len);
	if (ret == CKR_STATE_UNSAVEABLE) {
		TEST_OUT("Cannot save the operation state!\n");
		status = TEST_SKIP;
		goto end;
	} else if (CHECK_CK_RV(CKR_OK, "C_GetOperationState")) {
		goto end;
	}

	TEST_OUT("Decrypt data second part\n");
	decrypted_length = decrypted_data_size - index_data_1;
	ret = pfunc->C_DecryptUpdate(session, data2, sizeof(data2),
				     &decrypted_data_1[index_data_1],
				     &decrypted_length);
	index_data_1 += decrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Decrypt data third part\n");
	decrypted_length = decrypted_data_size - index_data_1;
	ret = pfunc->C_DecryptUpdate(session, data3, sizeof(data3),
				     &decrypted_data_1[index_data_1],
				     &decrypted_length);
	index_data_1 += decrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Finish decrypting data\n");
	decrypted_length = decrypted_data_size - index_data_1;
	ret = pfunc->C_DecryptFinal(session, &decrypted_data_1[index_data_1],
				    &decrypted_length);
	index_data_1 += decrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
		goto end;

	TEST_OUT("Set the saved operation state\n");
	ret = pfunc->C_SetOperationState(session, operation_state,
					 operation_state_len, CK_INVALID_HANDLE,
					 CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_OK, "C_SetOperationState"))
		goto end;

	TEST_OUT("Decrypt data second part\n");
	decrypted_length = decrypted_data_size - index_data_2;
	ret = pfunc->C_DecryptUpdate(session, data2, sizeof(data2),
				     &decrypted_data_2[index_data_2],
				     &decrypted_length);
	index_data_2 += decrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Decrypt data third part\n");
	decrypted_length = decrypted_data_size - index_data_2;
	ret = pfunc->C_DecryptUpdate(session, data3, sizeof(data3),
				     &decrypted_data_2[index_data_2],
				     &decrypted_length);
	index_data_2 += decrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	TEST_OUT("Finish decrypting data\n");
	decrypted_length = decrypted_data_size - index_data_2;
	ret = pfunc->C_DecryptFinal(session, &decrypted_data_2[index_data_2],
				    &decrypted_length);
	index_data_2 += decrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
		goto end;

	if (!util_compare_buffers(decrypted_data_2,
				  decrypted_data_size - skip_over,
				  decrypted_data_1 + skip_over,
				  decrypted_data_size - skip_over)) {
		TEST_OUT("decrypted_data_1 != decrypted_data_2\n");
		goto end;
	}

	status = TEST_PASS;

end:
	if (decrypted_data_1)
		free(decrypted_data_1);

	if (decrypted_data_2)
		free(decrypted_data_2);

	if (operation_state)
		free(operation_state);

	return status;
}

static int operation_state_sign_verify(CK_FUNCTION_LIST_PTR pfunc,
				       CK_SESSION_HANDLE session,
				       CK_MECHANISM_PTR sign_verify_mech,
				       CK_OBJECT_HANDLE hprivkey,
				       CK_OBJECT_HANDLE hpubkey)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;

	CK_BYTE_PTR signature_1 = NULL_PTR;
	CK_ULONG signature_len_1 = 0;
	CK_BYTE_PTR signature_2 = NULL_PTR;
	CK_ULONG signature_len_2 = 0;

	CK_BYTE_PTR operation_state_1 = NULL_PTR;
	CK_ULONG operation_state_len_1 = 0;
	CK_BYTE_PTR operation_state_2 = NULL_PTR;
	CK_ULONG operation_state_len_2 = 0;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(session, sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign the message first part\n");
	ret = pfunc->C_SignUpdate(session, data1, sizeof(data1));
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Get the size needed to save the operation state\n");
	ret = pfunc->C_GetOperationState(session, NULL_PTR,
					 &operation_state_len_1);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetOperationState"))
		goto end;

	TEST_OUT("Allocate the operation state buffer\n");
	operation_state_1 = calloc(1, operation_state_len_1);
	if (CHECK_EXPECTED(operation_state_1, "Allocation error"))
		goto end;

	TEST_OUT("Save the operation state\n");
	ret = pfunc->C_GetOperationState(session, operation_state_1,
					 &operation_state_len_1);
	if (ret == CKR_STATE_UNSAVEABLE) {
		TEST_OUT("Cannot save the operation state!\n");
		status = TEST_SKIP;
		goto end;
	} else if (CHECK_CK_RV(CKR_OK, "C_GetOperationState")) {
		goto end;
	}

	TEST_OUT("Sign the message second part\n");
	ret = pfunc->C_SignUpdate(session, data2, sizeof(data2));
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Sign the message third part\n");
	ret = pfunc->C_SignUpdate(session, data3, sizeof(data3));
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignFinal(session, signature_1, &signature_len_1);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	signature_1 = malloc(signature_len_1);
	if (CHECK_EXPECTED(signature_1, "Allocation error"))
		goto end;

	TEST_OUT("Finish multi-part sign operation\n");
	ret = pfunc->C_SignFinal(session, signature_1, &signature_len_1);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	TEST_OUT("Set the saved operation state\n");
	ret = pfunc->C_SetOperationState(session, operation_state_1,
					 operation_state_len_1,
					 CK_INVALID_HANDLE, CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_OK, "C_SetOperationState"))
		goto end;

	TEST_OUT("Sign the message second part\n");
	ret = pfunc->C_SignUpdate(session, data2, sizeof(data2));
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Sign the message third part\n");
	ret = pfunc->C_SignUpdate(session, data3, sizeof(data3));
	if (CHECK_CK_RV(CKR_OK, "C_SignUpdate"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_SignFinal(session, signature_2, &signature_len_2);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	signature_2 = malloc(signature_len_2);
	if (CHECK_EXPECTED(signature_2, "Allocation error"))
		goto end;

	TEST_OUT("Finish multi-part sign operation\n");
	ret = pfunc->C_SignFinal(session, signature_2, &signature_len_2);
	if (CHECK_CK_RV(CKR_OK, "C_SignFinal"))
		goto end;

	/*
	 * The 2 signatures may not a byte-for-byte match (e.g. ECDSA);
	 * Instead, print a message and verify the 2 signatures independently by
	 * using multi-part verify operations, also with C_GetOperationState
	 */
	if (util_compare_buffers(signature_2, signature_len_2, signature_1,
				 signature_len_1)) {
		TEST_OUT("Signatures match!\n");
	} else {
		TEST_OUT("Signatures do not match!\n");
	}

	TEST_OUT("Initialize first verify operation\n");
	ret = pfunc->C_VerifyInit(session, sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify the message first part\n");
	ret = pfunc->C_VerifyUpdate(session, data1, sizeof(data1));
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Get the size needed to save the operation state\n");
	ret = pfunc->C_GetOperationState(session, NULL_PTR,
					 &operation_state_len_2);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetOperationState"))
		goto end;

	TEST_OUT("Allocate the operation state buffer\n");
	operation_state_2 = calloc(1, operation_state_len_2);
	if (CHECK_EXPECTED(operation_state_2, "Allocation error"))
		goto end;

	TEST_OUT("Save the operation state\n");
	ret = pfunc->C_GetOperationState(session, operation_state_2,
					 &operation_state_len_2);
	if (ret == CKR_STATE_UNSAVEABLE) {
		TEST_OUT("Cannot save the operation state!\n");
		status = TEST_SKIP;
		goto end;
	} else if (CHECK_CK_RV(CKR_OK, "C_GetOperationState")) {
		goto end;
	}

	TEST_OUT("Verify the message second part\n");
	ret = pfunc->C_VerifyUpdate(session, data2, sizeof(data2));
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Verify the message third part\n");
	ret = pfunc->C_VerifyUpdate(session, data3, sizeof(data3));
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Finish multi-part verify operation\n");
	ret = pfunc->C_VerifyFinal(session, signature_1, signature_len_1);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
		goto end;

	TEST_OUT("Set the saved operation state\n");
	ret = pfunc->C_SetOperationState(session, operation_state_2,
					 operation_state_len_2,
					 CK_INVALID_HANDLE, CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_OK, "C_SetOperationState"))
		goto end;

	TEST_OUT("Verify the message second part\n");
	ret = pfunc->C_VerifyUpdate(session, data2, sizeof(data2));
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Verify the message third part\n");
	ret = pfunc->C_VerifyUpdate(session, data3, sizeof(data3));
	if (CHECK_CK_RV(CKR_OK, "C_VerifyUpdate"))
		goto end;

	TEST_OUT("Finish multi-part verify operation\n");
	ret = pfunc->C_VerifyFinal(session, signature_2, signature_len_2);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyFinal"))
		goto end;

	status = TEST_PASS;

end:
	if (operation_state_2)
		free(operation_state_2);

	if (operation_state_1)
		free(operation_state_1);

	if (signature_2)
		free(signature_2);

	if (signature_1)
		free(signature_1);

	return status;
}

static int operation_state_cipher_no_context(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_ULONG operation_state_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Call C_GetOperationState without operation\n");
	ret = pfunc->C_GetOperationState(session, NULL_PTR,
					 &operation_state_len);
	if (CHECK_CK_RV(CKR_OPERATION_NOT_INITIALIZED, "C_GetOperationState"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_cipher_bad_args(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_BYTE_PTR operation_state = NULL_PTR;
	CK_ULONG operation_state_len = 50;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Call C_GetOperationState with invalid handle\n");
	ret = pfunc->C_GetOperationState(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_GetOperationState"))
		goto end;

	TEST_OUT("Call C_GetOperationState with NULL length\n");
	ret = pfunc->C_GetOperationState(session, NULL_PTR, NULL_PTR);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_GetOperationState"))
		goto end;

	TEST_OUT("Call C_SetOperationState with invalid handle\n");
	ret = pfunc->C_SetOperationState(CK_INVALID_HANDLE, operation_state,
					 operation_state_len, CK_INVALID_HANDLE,
					 CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_SetOperationState"))
		goto end;

	TEST_OUT("Call C_SetOperationState with buffer length 0\n");
	ret = pfunc->C_SetOperationState(session, operation_state, 0,
					 CK_INVALID_HANDLE, CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_SetOperationState"))
		goto end;

	operation_state = malloc(1);
	if (CHECK_EXPECTED(operation_state, "Allocation error"))
		goto end;

	TEST_OUT("Call C_SetOperationState with hEncryptionKey\n");
	ret = pfunc->C_SetOperationState(session, operation_state, 1,
					 (CK_OBJECT_HANDLE)0xbad,
					 CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_KEY_NOT_NEEDED, "C_SetOperationState"))
		goto end;

	TEST_OUT("Call C_SetOperationState with hAuthenticationKey\n");
	ret = pfunc->C_SetOperationState(session, operation_state, 1,
					 CK_INVALID_HANDLE,
					 (CK_OBJECT_HANDLE)0xbad);
	if (CHECK_CK_RV(CKR_KEY_NOT_NEEDED, "C_SetOperationState"))
		goto end;

	TEST_OUT("Call C_SetOperationState with wrong state size\n");
	ret = pfunc->C_SetOperationState(session, operation_state, 1,
					 CK_INVALID_HANDLE, CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_SAVED_STATE_INVALID, "C_SetOperationState"))
		goto end;

	status = TEST_PASS;

end:
	if (operation_state)
		free(operation_state);

	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_cipher_aes(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	size_t i = 0;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_MECHANISM_TYPE aes_mech_type[] = {
		CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CTR, CKM_AES_CTS, CKM_AES_XTS,
	};
	CK_BYTE iv[] = { 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			 0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG key_length = 16;
	CK_MECHANISM aes_key_mech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_MECHANISM_TYPE key_allowed_mech[] = { (CK_MECHANISM_TYPE)0 };
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;
	CK_ATTRIBUTE aes_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_BYTE key_value[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
	CK_ATTRIBUTE xts_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &ck_false, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE, &key_value, sizeof(key_value) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_MECHANISM encrypt_decrypt_mech = { 0 };
	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_AES_CTR_PARAMS ctr_params = { .cb = { 0x00, 0x01, 0x02, 0x03, 0x04,
						 0x05, 0x06, 0x07 },
					 .ulCounterBits = 64 };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(aes_mech_type); i++) {
		encrypt_decrypt_mech.pParameter = NULL_PTR;
		encrypt_decrypt_mech.ulParameterLen = 0;
		encrypt_decrypt_mech.mechanism = aes_mech_type[i];
		key_allowed_mech[0] = aes_mech_type[i];

		if (encrypt_decrypt_mech.mechanism == CKM_AES_XTS) {
			TEST_OUT("Createobject AES secret Key\n");
			ret = pfunc->C_CreateObject(session, xts_key_attrs,
						    ARRAY_SIZE(xts_key_attrs),
						    &aes_hsecretkey);
			if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
				goto end;
		} else {
			TEST_OUT("Generate AES secret Key\n");
			ret = pfunc->C_GenerateKey(session, &aes_key_mech,
						   aes_key_attrs,
						   ARRAY_SIZE(aes_key_attrs),
						   &aes_hsecretkey);
			if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
				goto end;
		}

		switch (encrypt_decrypt_mech.mechanism) {
		case CKM_AES_ECB:
			break;

		case CKM_AES_CTR:
			encrypt_decrypt_mech.pParameter = &ctr_params;
			encrypt_decrypt_mech.ulParameterLen =
				sizeof(ctr_params);
			break;

		case CKM_AES_CBC:
		case CKM_AES_CTS:
		case CKM_AES_XTS:
			encrypt_decrypt_mech.pParameter = iv;
			encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
			break;

		default:
			break;
		}

		status = operation_state_cipher_encrypt(pfunc, session,
							&encrypt_decrypt_mech,
							aes_hsecretkey);
		if (status == TEST_FAIL)
			goto end;

		status = operation_state_cipher_decrypt(pfunc, session,
							&encrypt_decrypt_mech,
							aes_hsecretkey);
		if (status == TEST_FAIL)
			goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_cipher_des(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	size_t i = 0;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_MECHANISM_TYPE des_mech_type[] = {
		CKM_DES_ECB,
		CKM_DES_CBC,
	};
	CK_BYTE iv[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	CK_MECHANISM des_key_mech = { .mechanism = CKM_DES_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_MECHANISM_TYPE key_allowed_mech[] = { (CK_MECHANISM_TYPE)0 };
	CK_BBOOL ck_true = CK_TRUE;
	CK_ATTRIBUTE des_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_MECHANISM encrypt_decrypt_mech = { 0 };
	CK_OBJECT_HANDLE des_hsecretkey = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(des_mech_type); i++) {
		encrypt_decrypt_mech.pParameter = NULL_PTR;
		encrypt_decrypt_mech.ulParameterLen = 0;
		encrypt_decrypt_mech.mechanism = des_mech_type[i];
		key_allowed_mech[0] = des_mech_type[i];

		if (!util_lib_is_mech_supported(pfunc, 0, des_mech_type[i]))
			continue;

		ret = pfunc->C_GenerateKey(session, &des_key_mech,
					   des_key_attrs,
					   ARRAY_SIZE(des_key_attrs),
					   &des_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
			goto end;

		switch (encrypt_decrypt_mech.mechanism) {
		case CKM_DES_ECB:
			break;

		case CKM_DES_CBC:
			encrypt_decrypt_mech.pParameter = iv;
			encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
			break;

		default:
			break;
		}

		status = operation_state_cipher_encrypt(pfunc, session,
							&encrypt_decrypt_mech,
							des_hsecretkey);
		if (status == TEST_FAIL)
			goto end;

		status = operation_state_cipher_decrypt(pfunc, session,
							&encrypt_decrypt_mech,
							des_hsecretkey);
		if (status == TEST_FAIL)
			goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_cipher_des3(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	size_t i = 0;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_MECHANISM_TYPE des_mech_type[] = {
		CKM_DES3_ECB,
		CKM_DES3_CBC,
	};
	CK_BYTE iv[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	CK_MECHANISM des3_key_mech = { .mechanism = CKM_DES3_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_MECHANISM_TYPE key_allowed_mech[] = { (CK_MECHANISM_TYPE)0 };
	CK_BBOOL ck_true = CK_TRUE;
	CK_ATTRIBUTE des3_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_MECHANISM encrypt_decrypt_mech = { 0 };
	CK_OBJECT_HANDLE des3_hsecretkey = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(des_mech_type); i++) {
		encrypt_decrypt_mech.pParameter = NULL_PTR;
		encrypt_decrypt_mech.ulParameterLen = 0;
		encrypt_decrypt_mech.mechanism = des_mech_type[i];
		key_allowed_mech[0] = des_mech_type[i];

		if (!util_lib_is_mech_supported(pfunc, 0, des_mech_type[i]))
			continue;

		ret = pfunc->C_GenerateKey(session, &des3_key_mech,
					   des3_key_attrs,
					   ARRAY_SIZE(des3_key_attrs),
					   &des3_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
			goto end;

		switch (encrypt_decrypt_mech.mechanism) {
		case CKM_DES3_ECB:
			break;

		case CKM_DES3_CBC:
			encrypt_decrypt_mech.pParameter = iv;
			encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
			break;

		default:
			break;
		}

		status = operation_state_cipher_encrypt(pfunc, session,
							&encrypt_decrypt_mech,
							des3_hsecretkey);
		if (status == TEST_FAIL)
			goto end;

		status = operation_state_cipher_decrypt(pfunc, session,
							&encrypt_decrypt_mech,
							des3_hsecretkey);
		if (status == TEST_FAIL)
			goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_cipher_sm4(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	size_t i = 0;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_MECHANISM_TYPE sm4_mech_type[] = {
		CKM_SM4_CBC,
		CKM_SM4_CTR,
		CKM_SM4_ECB,
	};
	CK_BYTE iv[] = { 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			 0x09, 0x010, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_SM4_CTR_PARAMS ctr_params = {
		.cb = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		.ulCounterBits = 64
	};
	CK_ULONG key_length = 128 / 8;

	CK_MECHANISM sm4_key_mech = { .mechanism = CKM_SM4_KEY_GEN };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_MECHANISM_TYPE key_allowed_mech[] = { (CK_MECHANISM_TYPE)0 };
	CK_BBOOL ck_true = CK_TRUE;
	CK_ATTRIBUTE sm4_key_attrs[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &key_length, sizeof(CK_ULONG) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_MECHANISM encrypt_decrypt_mech = { 0 };
	CK_OBJECT_HANDLE sm4_hsecretkey = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ARRAY_SIZE(sm4_mech_type); i++) {
		encrypt_decrypt_mech.pParameter = NULL_PTR;
		encrypt_decrypt_mech.ulParameterLen = 0;
		encrypt_decrypt_mech.mechanism = sm4_mech_type[i];
		key_allowed_mech[0] = sm4_mech_type[i];

		if (!util_lib_is_mech_supported(pfunc, 0, sm4_mech_type[i]))
			continue;

		ret = pfunc->C_GenerateKey(session, &sm4_key_mech,
					   sm4_key_attrs,
					   ARRAY_SIZE(sm4_key_attrs),
					   &sm4_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
			goto end;

		switch (encrypt_decrypt_mech.mechanism) {
		case CKM_SM4_ECB:
			break;

		case CKM_SM4_CBC:
			encrypt_decrypt_mech.pParameter = iv;
			encrypt_decrypt_mech.ulParameterLen = ARRAY_SIZE(iv);
			break;

		case CKM_SM4_CTR:
			encrypt_decrypt_mech.pParameter = &ctr_params;
			encrypt_decrypt_mech.ulParameterLen =
				sizeof(ctr_params);
			break;

		default:
			break;
		}

		status = operation_state_cipher_encrypt(pfunc, session,
							&encrypt_decrypt_mech,
							sm4_hsecretkey);
		if (status == TEST_FAIL)
			goto end;

		status = operation_state_cipher_decrypt(pfunc, session,
							&encrypt_decrypt_mech,
							sm4_hsecretkey);
		if (status == TEST_FAIL)
			goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_sign_verify_ecdsa(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };

	CK_OBJECT_HANDLE hpubkey;
	CK_OBJECT_HANDLE hprivkey;
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

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate EC Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(session, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	status = operation_state_sign_verify(pfunc, session, &sign_verify_mech,
					     hprivkey, hpubkey);
end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_sign_verify_rsa_pss(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_RSA_PKCS_PSS };
	CK_RSA_PKCS_PSS_PARAMS pss_params = { 0 };

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

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	pss_params.hashAlg = CKM_SHA384;
	pss_params.sLen = 48;
	sign_verify_mech.pParameter = &pss_params;
	sign_verify_mech.ulParameterLen = sizeof(pss_params);

	TEST_OUT("Generate RSA Keypair\n");
	ret = pfunc->C_GenerateKeyPair(session, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	status = operation_state_sign_verify(pfunc, session, &sign_verify_mech,
					     hprivkey, hpubkey);

end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_sign_verify_rsa_pkcs(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE session = 0;

	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA512_RSA_PKCS };

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

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(session, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate RSA Keypair\n");
	ret = pfunc->C_GenerateKeyPair(session, &key_mech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	status = operation_state_sign_verify(pfunc, session, &sign_verify_mech,
					     hprivkey, hpubkey);

end:
	util_close_session(pfunc, &session);

	SUBTEST_END(status);
	return status;
}

static int operation_state_digest(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	CK_RV ret = CKR_OK;

	enum mechanism_id id = MECH_ID_SHA256;
	CK_MECHANISM digest_mech = { 0 };
	CK_SESSION_HANDLE session = 0;
	CK_BYTE_PTR operation_state = NULL_PTR;
	CK_ULONG operation_state_len = 0;
	CK_BYTE_PTR message = NULL_PTR;
	CK_ULONG total_message_length = 0;
	CK_ULONG message_part_length = 0;
	CK_BYTE_PTR digest_1 = NULL_PTR;
	CK_ULONG digest_length_1 = 0;
	CK_BYTE_PTR digest_2 = NULL_PTR;
	CK_ULONG digest_length_2 = 0;
	bool match = false;

	digest_mech.mechanism = DIGEST_MECHANISM(id);

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &session) != TEST_PASS)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, digest_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(session, &digest_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	digest_length_1 = DIGEST_LENGTH(id);
	digest_1 = malloc(digest_length_1);
	if (CHECK_EXPECTED(digest_1, "Allocation error"))
		goto end;

	message = (CK_BYTE_PTR)TV_MSG(id);
	total_message_length = TV_MSG_LEN(id);
	message_part_length = total_message_length / 2;

	TEST_OUT("Call C_DigestUpdate with first part of data\n");
	ret = pfunc->C_DigestUpdate(session, message, message_part_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Get the size needed to save the operation state\n");
	ret = pfunc->C_GetOperationState(session, NULL_PTR,
					 &operation_state_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetOperationState"))
		goto end;

	TEST_OUT("Allocate the operation state buffer\n");
	operation_state = calloc(1, operation_state_len);
	if (CHECK_EXPECTED(operation_state, "Allocation error"))
		goto end;

	TEST_OUT("Save the operation state\n");
	ret = pfunc->C_GetOperationState(session, operation_state,
					 &operation_state_len);
	if (ret == CKR_STATE_UNSAVEABLE) {
		TEST_OUT("Cannot save the operation state!\n");
		status = TEST_SKIP;
		goto end;
	} else if (CHECK_CK_RV(CKR_OK, "C_GetOperationState")) {
		goto end;
	}

	TEST_OUT("Call C_DigestUpdate with second part of data\n");
	ret = pfunc->C_DigestUpdate(session, message + message_part_length,
				    total_message_length - message_part_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Finalize the multi-part digest operation\n");
	ret = pfunc->C_DigestFinal(session, digest_1, &digest_length_1);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	match = check_digest(TV_DIGEST(id), DIGEST_LENGTH(id), digest_1,
			     digest_length_1);
	if (CHECK_EXPECTED(match, "Digest mismatch"))
		goto end;

	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(session, &digest_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	TEST_OUT("Call C_DigestUpdate with first part of data\n");
	ret = pfunc->C_DigestUpdate(session, message, message_part_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	/*
	 * Cancels the on-going digest multi-part operation and restores the
	 * saved operation state.
	 */
	TEST_OUT("Retrieve the saved operation state\n");
	ret = pfunc->C_SetOperationState(session, operation_state,
					 operation_state_len, CK_INVALID_HANDLE,
					 CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_OK, "C_SetOperationState"))
		goto end;

	digest_length_2 = DIGEST_LENGTH(id);
	digest_2 = malloc(digest_length_2);
	if (CHECK_EXPECTED(digest_2, "Allocation error"))
		goto end;

	TEST_OUT("Call C_DigestUpdate with second part of data\n");
	ret = pfunc->C_DigestUpdate(session, message + message_part_length,
				    total_message_length - message_part_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Finalize the multi-part digest operation\n");
	ret = pfunc->C_DigestFinal(session, digest_2, &digest_length_2);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	if (!util_compare_buffers(digest_1, digest_length_1, digest_2,
				  digest_length_2)) {
		TEST_OUT("Digest do not match!\n");
		goto end;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &session);

	if (operation_state)
		free(operation_state);

	if (digest_1)
		free(digest_1);

	if (digest_2)
		free(digest_2);

	SUBTEST_END(status);
	return status;
}

static int generate_cipher_key(CK_FUNCTION_LIST_PTR pfunc,
			       CK_SESSION_HANDLE_PTR sess,
			       CK_OBJECT_HANDLE_PTR hkey)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_ULONG key_len = 16;
	CK_BBOOL btrue = CK_TRUE;
	CK_MECHANISM_TYPE key_allowed_mech = CKM_AES_ECB;

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) }
	};

	TEST_OUT("Generate Cipher key\n");
	ret = pfunc->C_GenerateKey(*sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), hkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Key generated #%lu\n", *hkey);

	status = TEST_PASS;

end:
	return status;
}

static int is_expected_key(CK_OBJECT_HANDLE_PTR hkey, CK_OBJECT_HANDLE_PTR hexp,
			   size_t nb_exp)
{
	size_t idx = 0;

	if (!hkey || !hexp || !nb_exp)
		return 0;

	for (; idx < nb_exp; idx++)
		if (hexp[idx] != CK_INVALID_HANDLE && *hkey == hexp[idx])
			return 1;

	return 0;
}

static int operation_state_find_object(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE hkeys[NB_KEYS_HDL] = { 0 };
	CK_OBJECT_HANDLE hkeys_match[NB_KEYS_HDL] = { 0 };
	CK_SESSION_HANDLE sess = 0;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_BBOOL token = CK_FALSE;
	CK_BYTE_PTR operation_state = NULL_PTR;
	CK_ULONG operation_state_len = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	CK_ULONG nb_match = 0;
	unsigned int i = 0;
	int match = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < NB_KEYS_HDL; i++) {
		if (generate_cipher_key(pfunc, &sess, &hkeys[i]) == TEST_FAIL)
			goto end;
	}

	TEST_OUT("Initialize find operation\n");
	ret = pfunc->C_FindObjectsInit(sess, match_attrs,
				       ARRAY_SIZE(match_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	TEST_OUT("Get the size needed to save the operation state\n");
	ret = pfunc->C_GetOperationState(sess, NULL_PTR, &operation_state_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetOperationState"))
		goto end;

	TEST_OUT("Allocate the operation state buffer\n");
	operation_state = calloc(1, operation_state_len);
	if (CHECK_EXPECTED(operation_state, "Allocation error"))
		goto end;

	TEST_OUT("Save the operation state\n");
	ret = pfunc->C_GetOperationState(sess, operation_state,
					 &operation_state_len);
	if (ret == CKR_STATE_UNSAVEABLE) {
		TEST_OUT("Cannot save the operation state!\n");
		status = TEST_SKIP;
		goto end;
	} else if (CHECK_CK_RV(CKR_OK, "C_GetOperationState")) {
		goto end;
	}

	TEST_OUT("Find Cipher AES keys\n");
	ret = pfunc->C_FindObjects(sess, hkeys_match, NB_KEYS_HDL, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	if (CHECK_EXPECTED(nb_match == NB_KEYS_HDL,
			   "Got %lu but expected %d objects", nb_match,
			   NB_KEYS_HDL))
		goto end;

	TEST_OUT("Terminate the active find operation\n");
	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	TEST_OUT("Retrieve the saved operation state\n");
	ret = pfunc->C_SetOperationState(sess, operation_state,
					 operation_state_len, CK_INVALID_HANDLE,
					 CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_OK, "C_SetOperationState"))
		goto end;

	nb_match = 0;
	memset(hkeys_match, 0, sizeof(hkeys_match));

	TEST_OUT("Find Cipher AES keys after restoring operation state\n");
	ret = pfunc->C_FindObjects(sess, hkeys_match, NB_KEYS_HDL, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	TEST_OUT("Terminate the active find operation\n");
	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == NB_KEYS_HDL,
			   "Got %lu but expected %d objects", nb_match,
			   NB_KEYS_HDL))
		goto end;

	TEST_OUT("Compare keys\n");
	for (i = 0; i < NB_KEYS_HDL; i++) {
		match = is_expected_key(&hkeys_match[i], hkeys, nb_match);
		if (CHECK_EXPECTED(match, "Key #%lu not expected",
				   hkeys_match[i]))
			goto end;
	}

	status = TEST_PASS;

end:
	for (i = 0; i < NB_KEYS_HDL; i++) {
		TEST_OUT("Destroy key #%lu\n", hkeys[i]);
		if (hkeys[i] != CK_INVALID_HANDLE) {
			ret = pfunc->C_DestroyObject(sess, hkeys[i]);
			if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
				status = TEST_FAIL;
		}
	}

	util_close_session(pfunc, &sess);

	if (operation_state)
		free(operation_state);

	SUBTEST_END(status);
	return status;
}

static int operation_state_find_digest_encrypt(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE hkeys[NB_KEYS_HDL] = { 0 };
	CK_OBJECT_HANDLE hkeys_match[NB_KEYS_HDL] = { 0 };
	CK_SESSION_HANDLE sess = 0;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_BBOOL token = CK_FALSE;
	CK_BYTE_PTR operation_state = NULL_PTR;
	CK_ULONG operation_state_len = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
	};

	CK_MECHANISM encrypt_mech = { CKM_AES_ECB, NULL_PTR, 0 };

	enum mechanism_id id = MECH_ID_SHA256;
	CK_MECHANISM digest_mech = { 0 };

	CK_ULONG nb_match = 0;
	unsigned int i = 0;
	int match = 0;

	CK_BYTE_PTR message = NULL_PTR;
	CK_ULONG total_message_length = 0;
	CK_ULONG message_part_length = 0;
	CK_BYTE_PTR digest_1 = NULL_PTR;
	CK_ULONG digest_length_1 = 0;
	CK_BYTE_PTR digest_2 = NULL_PTR;
	CK_ULONG digest_length_2 = 0;

	CK_ULONG encrypted_length = 0;
	CK_BYTE_PTR encrypted_data_1 = NULL_PTR;
	CK_ULONG index_data_1 = 0;
	CK_BYTE_PTR encrypted_data_2 = NULL_PTR;
	CK_ULONG index_data_2 = 0;
	CK_ULONG skip_over = 0;
	CK_ULONG encrypted_data_size = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < NB_KEYS_HDL; i++) {
		if (generate_cipher_key(pfunc, &sess, &hkeys[i]) == TEST_FAIL)
			goto end;
	}

	TEST_OUT("Initialize find operation\n");
	ret = pfunc->C_FindObjectsInit(sess, match_attrs,
				       ARRAY_SIZE(match_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	digest_mech.mechanism = DIGEST_MECHANISM(id);
	TEST_OUT("Initialize digest operation\n");
	ret = pfunc->C_DigestInit(sess, &digest_mech);
	if (CHECK_CK_RV(CKR_OK, "C_DigestInit"))
		goto end;

	digest_length_1 = DIGEST_LENGTH(id);
	digest_1 = malloc(digest_length_1);
	if (CHECK_EXPECTED(digest_1, "Allocation error"))
		goto end;

	message = (CK_BYTE_PTR)TV_MSG(id);
	total_message_length = TV_MSG_LEN(id);
	message_part_length = total_message_length / 2;

	TEST_OUT("Call C_DigestUpdate with first part of data\n");
	ret = pfunc->C_DigestUpdate(sess, message, message_part_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	encrypted_data_size =
		sizeof(data1) + sizeof(data2) + sizeof(data3) + 64;

	TEST_OUT("Allocate first encrypted data\n");
	encrypted_data_1 = calloc(1, encrypted_data_size);
	if (CHECK_EXPECTED(encrypted_data_1, "Allocation error"))
		goto end;

	TEST_OUT("Allocate second encrypted data\n");
	encrypted_data_2 = calloc(1, encrypted_data_size);
	if (CHECK_EXPECTED(encrypted_data_2, "Allocation error"))
		goto end;

	TEST_OUT("Initialize encryption operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_mech, hkeys[0]);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	TEST_OUT("Encrypt data first part\n");
	encrypted_length = encrypted_data_size;
	ret = pfunc->C_EncryptUpdate(sess, data1, sizeof(data1),
				     &encrypted_data_1[index_data_1],
				     &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	/*
	 * This ciphertext is only part of encrypted_data_1, because the operation
	 * state is saved after it is computed.
	 */
	skip_over = index_data_1;

	TEST_OUT("Get the size needed to save the operation state\n");
	ret = pfunc->C_GetOperationState(sess, NULL_PTR, &operation_state_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetOperationState"))
		goto end;

	TEST_OUT("Allocate the operation state buffer\n");
	operation_state = calloc(1, operation_state_len);
	if (CHECK_EXPECTED(operation_state, "Allocation error"))
		goto end;

	/*
	 * C_GetOperationState should save the operation state of
	 *  1. Find object operation
	 *  2. Digest multi-part operation
	 *  3. Encrypt multi-part operation
	 */
	TEST_OUT("Save the operation state\n");
	ret = pfunc->C_GetOperationState(sess, operation_state,
					 &operation_state_len);
	if (ret == CKR_STATE_UNSAVEABLE) {
		TEST_OUT("Cannot save the operation state!\n");
		status = TEST_SKIP;
		goto end;
	} else if (CHECK_CK_RV(CKR_OK, "C_GetOperationState")) {
		goto end;
	}

	TEST_OUT("Find Cipher AES keys\n");
	ret = pfunc->C_FindObjects(sess, hkeys_match, NB_KEYS_HDL, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	if (CHECK_EXPECTED(nb_match == NB_KEYS_HDL,
			   "Got %lu but expected %d objects", nb_match,
			   NB_KEYS_HDL))
		goto end;

	TEST_OUT("Terminate the active find operation\n");
	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	TEST_OUT("Call C_DigestUpdate with second part of data\n");
	ret = pfunc->C_DigestUpdate(sess, message + message_part_length,
				    total_message_length - message_part_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Finalize the multi-part digest operation\n");
	ret = pfunc->C_DigestFinal(sess, digest_1, &digest_length_1);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	match = check_digest(TV_DIGEST(id), DIGEST_LENGTH(id), digest_1,
			     digest_length_1);
	if (CHECK_EXPECTED(match, "Digest mismatch"))
		goto end;

	TEST_OUT("Encrypt data second part\n");
	encrypted_length = encrypted_data_size - index_data_1;
	ret = pfunc->C_EncryptUpdate(sess, data2, sizeof(data2),
				     &encrypted_data_1[index_data_1],
				     &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Encrypt data third part\n");
	encrypted_length = encrypted_data_size - index_data_1;
	ret = pfunc->C_EncryptUpdate(sess, data3, sizeof(data3),
				     &encrypted_data_1[index_data_1],
				     &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Finish encrypting data\n");
	encrypted_length = encrypted_data_size - index_data_1;
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data_1[index_data_1],
				    &encrypted_length);
	index_data_1 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	/*
	 * C_SetOperationState should retrieve operation states of
	 *  1. Find object operation
	 *  2. Digest multi-part operation
	 *  3. Encrypt multi-part operation
	 */
	TEST_OUT("Retrieve the saved operation state\n");
	ret = pfunc->C_SetOperationState(sess, operation_state,
					 operation_state_len, CK_INVALID_HANDLE,
					 CK_INVALID_HANDLE);
	if (CHECK_CK_RV(CKR_OK, "C_SetOperationState"))
		goto end;

	nb_match = 0;
	memset(hkeys_match, 0, sizeof(hkeys_match));

	TEST_OUT("Find Cipher AES keys after restoring operation state\n");
	ret = pfunc->C_FindObjects(sess, hkeys_match, NB_KEYS_HDL, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	TEST_OUT("Terminate the active find operation\n");
	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == NB_KEYS_HDL,
			   "Got %lu but expected %d objects", nb_match,
			   NB_KEYS_HDL))
		goto end;

	TEST_OUT("Compare keys\n");
	for (i = 0; i < NB_KEYS_HDL; i++) {
		match = is_expected_key(&hkeys_match[i], hkeys, nb_match);
		if (CHECK_EXPECTED(match, "Key #%lu not expected",
				   hkeys_match[i]))
			goto end;
	}

	digest_length_2 = DIGEST_LENGTH(id);
	digest_2 = malloc(digest_length_2);
	if (CHECK_EXPECTED(digest_2, "Allocation error"))
		goto end;

	TEST_OUT("Continue with C_DigestUpdate after restoring op state\n");
	ret = pfunc->C_DigestUpdate(sess, message + message_part_length,
				    total_message_length - message_part_length);
	if (CHECK_CK_RV(CKR_OK, "C_DigestUpdate"))
		goto end;

	TEST_OUT("Finalize the multi-part digest operation\n");
	ret = pfunc->C_DigestFinal(sess, digest_2, &digest_length_2);
	if (CHECK_CK_RV(CKR_OK, "C_DigestFinal"))
		goto end;

	if (!util_compare_buffers(digest_1, digest_length_1, digest_2,
				  digest_length_2)) {
		TEST_OUT("Digest do not match!\n");
		goto end;
	}

	TEST_OUT("Continue with C_EncryptUpdate after restoring op state\n");
	/* Encrypt second part of data */
	encrypted_length = encrypted_data_size - index_data_2;
	ret = pfunc->C_EncryptUpdate(sess, data2, sizeof(data2),
				     &encrypted_data_2[index_data_2],
				     &encrypted_length);
	index_data_2 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Encrypt data third part\n");
	encrypted_length = encrypted_data_size - index_data_2;
	ret = pfunc->C_EncryptUpdate(sess, data3, sizeof(data3),
				     &encrypted_data_2[index_data_2],
				     &encrypted_length);
	index_data_2 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	TEST_OUT("Finish encrypting data\n");
	encrypted_length = encrypted_data_size - index_data_2;
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data_2[index_data_2],
				    &encrypted_length);
	index_data_2 += encrypted_length;
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	if (!util_compare_buffers(encrypted_data_2,
				  encrypted_data_size - skip_over,
				  encrypted_data_1 + skip_over,
				  encrypted_data_size - skip_over)) {
		TEST_OUT("encrypted_data_1 != encrypted_data_2\n");
		goto end;
	}

	status = TEST_PASS;

end:
	for (i = 0; i < NB_KEYS_HDL; i++) {
		TEST_OUT("Destroy key #%lu\n", hkeys[i]);
		if (hkeys[i] != CK_INVALID_HANDLE) {
			ret = pfunc->C_DestroyObject(sess, hkeys[i]);
			if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
				status = TEST_FAIL;
		}
	}

	util_close_session(pfunc, &sess);

	if (operation_state)
		free(operation_state);

	if (encrypted_data_1)
		free(encrypted_data_1);

	if (encrypted_data_2)
		free(encrypted_data_2);

	if (digest_1)
		free(digest_1);

	if (digest_2)
		free(digest_2);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_operation_state(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (operation_state_cipher_no_context(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_cipher_bad_args(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_cipher_aes(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_cipher_des(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_cipher_des3(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_cipher_sm4(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_sign_verify_ecdsa(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_sign_verify_rsa_pss(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_sign_verify_rsa_pkcs(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_digest(pfunc) == TEST_FAIL)
		goto end;

	if (operation_state_find_object(pfunc) == TEST_FAIL)
		goto end;

	status = operation_state_find_digest_encrypt(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
