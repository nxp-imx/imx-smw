// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>
#include <psa/internal_trusted_storage.h>

#include <smw_status.h>
#include <smw/object.h>

#include "os_mutex.h"
#include "util_lib.h"
#include "util_session.h"
#include "util.h"

/* messagetosign */
static CK_BYTE msg[] = { 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
			 0x74, 0x6f, 0x73, 0x69, 0x67, 0x6e };

static CK_ULONG msg_len = 13;

static CK_BYTE data[] =
	"message to encrypt using symmetric crypto algo (AES, DES, DES3)";

static int encrypt_decrypt_aes(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t psa_id = PSA_KEY_ID_NULL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL btrue = CK_TRUE;

	psa_key_type_t key_type = PSA_KEY_TYPE_AES;

	CK_MECHANISM_TYPE aes_mech_type[] = { CKM_AES_CBC, CKM_AES_CTR };

	psa_algorithm_t aes_algo_type[] = { PSA_ALG_CBC_NO_PADDING,
					    PSA_ALG_CTR };

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
	CK_ULONG data_len = sizeof(data);
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;

	CK_AES_CTR_PARAMS ctr_params = { 0 };
	CK_OBJECT_HANDLE aes_hsecretkey = 0;
	CK_ULONG nb_match = 0;

	/* AES - 256 bits key length */
	CK_ULONG key_length = 32;
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL_PTR;

	CK_ATTRIBUTE aes_key_attrs[] = {
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};
	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Initialize PSA Crypto */
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS)
		goto end;

	encrypted_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	recovered_data = (CK_BYTE_PTR)calloc(data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	for (; i < ARRAY_SIZE(aes_algo_type); i++) {
		encrypt_decrypt_mech.pParameter = NULL_PTR;
		encrypt_decrypt_mech.ulParameterLen = 0;
		encrypt_decrypt_mech.mechanism = aes_mech_type[i];

		if (!util_lib_is_mech_supported(pfunc, 0, aes_mech_type[i]))
			continue;

		TEST_OUT("Generate AES secret Key\n");
		/* Set key attributes */
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
		psa_set_key_usage_flags(&attributes,
					PSA_KEY_USAGE_ENCRYPT |
						PSA_KEY_USAGE_DECRYPT);
		psa_set_key_type(&attributes, key_type);
		psa_set_key_bits(&attributes, BYTES_TO_BITS(key_length));
		psa_set_key_algorithm(&attributes, aes_algo_type[i]);

		/* Generate the key */
		psa_status = psa_generate_key(&attributes, &psa_id);
		if (psa_status != PSA_SUCCESS)
			goto end;

		ret = util_set_unique_id(unique_id, &unique_id_len,
					 secret_key_class, psa_id);
		if (ret != CKR_BUFFER_TOO_SMALL)
			goto end;

		unique_id = calloc(1, unique_id_len);
		if (!unique_id)
			goto end;

		ret = util_set_unique_id(unique_id, &unique_id_len,
					 secret_key_class, psa_id);
		if (ret != CKR_OK)
			goto end;

		aes_key_attrs[0].pValue = unique_id;
		aes_key_attrs[0].ulValueLen = unique_id_len;

		TEST_OUT("Find Cipher AES keys\n");
		ret = pfunc->C_FindObjectsInit(sess, aes_key_attrs,
					       ARRAY_SIZE(aes_key_attrs));
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
			goto end;

		ret = pfunc->C_FindObjects(sess, &aes_hsecretkey, 1, &nb_match);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
			goto end;

		ret = pfunc->C_FindObjectsFinal(sess);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
			goto end;

		if (CHECK_EXPECTED(nb_match == 1,
				   "Got %lu but expected one object", nb_match))
			goto end;

		if (!is_seco_subsystem()) {
			TEST_OUT("Initialize encrypt operation\n");

			switch (encrypt_decrypt_mech.mechanism) {
			case CKM_AES_CBC:
				encrypt_decrypt_mech.pParameter = iv;
				encrypt_decrypt_mech.ulParameterLen =
					sizeof(iv);
				break;

			case CKM_AES_CTR:
				memcpy(ctr_params.cb, counter_block,
				       sizeof(counter_block));
				ctr_params.ulCounterBits = counter_bits;
				encrypt_decrypt_mech.pParameter = &ctr_params;
				encrypt_decrypt_mech.ulParameterLen =
					sizeof(ctr_params);
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
			ret = pfunc->C_Encrypt(sess, data, data_len,
					       encrypted_data,
					       &encrypted_data_len);
			if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Encrypt"))
				goto end;

			TEST_OUT("Encrypt message\n");
			ret = pfunc->C_Encrypt(sess, data, data_len,
					       encrypted_data,
					       &encrypted_data_len);
			if (CHECK_CK_RV(CKR_OK, "C_Encrypt"))
				goto end;

			TEST_OUT("Initialize decrypt operation\n");
			ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
						   aes_hsecretkey);
			if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
				goto end;

			ret = pfunc->C_Decrypt(sess, encrypted_data,
					       encrypted_data_len, NULL_PTR,
					       &recovered_data_len);
			if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
				goto end;

			TEST_OUT("Decrypt encrypted data\n");
			ret = pfunc->C_Decrypt(sess, encrypted_data,
					       encrypted_data_len,
					       recovered_data,
					       &recovered_data_len);
			if (CHECK_CK_RV(CKR_OK, "C_Decrypt"))
				goto end;

			TEST_OUT("Decrypted data = %s length = 0x%lx\n",
				 recovered_data, recovered_data_len);

			if (!util_compare_buffers(data, data_len,
						  recovered_data,
						  recovered_data_len)) {
				TEST_OUT("Decrypted data != plaintext data\n");
				goto end;
			}
		} else {
			TEST_OUT("Get key attributes not supported\n");
		}

		TEST_OUT("Key Destroy #%lu\n", aes_hsecretkey);
		ret = pfunc->C_DestroyObject(sess, aes_hsecretkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;

		/* Free the attributes */
		psa_reset_key_attributes(&attributes);

		/* Destroy the key */
		psa_destroy_key(psa_id);

		free(unique_id);
		unique_id = NULL_PTR;
		unique_id_len = 0;
	}

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	if (psa_id)
		psa_destroy_key(psa_id);

	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	if (unique_id)
		free(unique_id);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_ecdsa(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t psa_id = PSA_KEY_ID_NULL;
	psa_key_type_t key_type =
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
	psa_algorithm_t ecdsa_algo_type = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

	CK_RV ret = CKR_OK;
	CK_BBOOL btrue = CK_TRUE;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_ULONG nb_match = 0;

	CK_ULONG key_length = 32;
	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL_PTR;
	CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE public_key_attrs[] = {
		{ CKA_CLASS, &public_key_class, sizeof(public_key_class) },
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	CK_ATTRIBUTE private_key_attrs[] = {
		{ CKA_CLASS, &private_key_class, sizeof(private_key_class) },
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Initialize PSA Crypto */
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS)
		goto end;

	/* Set key attributes */
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_SIGN_MESSAGE |
					PSA_KEY_USAGE_SIGN_HASH |
					PSA_KEY_USAGE_VERIFY_MESSAGE |
					PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_type(&attributes, key_type);
	psa_set_key_bits(&attributes, BYTES_TO_BITS(key_length));
	psa_set_key_algorithm(&attributes, ecdsa_algo_type);

	psa_status = psa_generate_key(&attributes, &psa_id);
	if (psa_status != PSA_SUCCESS)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, public_key_class,
				 psa_id);
	if (ret != CKR_BUFFER_TOO_SMALL)
		goto end;

	unique_id = calloc(1, unique_id_len);
	if (!unique_id)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, public_key_class,
				 psa_id);
	if (ret != CKR_OK)
		goto end;

	public_key_attrs[1].pValue = unique_id;
	public_key_attrs[1].ulValueLen = unique_id_len;

	TEST_OUT("Find ECDSA public key\n");
	ret = pfunc->C_FindObjectsInit(sess, public_key_attrs,
				       ARRAY_SIZE(public_key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hpubkey, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	free(unique_id);
	unique_id = NULL_PTR;
	unique_id_len = 0;

	ret = util_set_unique_id(unique_id, &unique_id_len, private_key_class,
				 psa_id);
	if (ret != CKR_BUFFER_TOO_SMALL)
		goto end;

	unique_id = calloc(1, unique_id_len);
	if (!unique_id)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, private_key_class,
				 psa_id);
	if (ret != CKR_OK)
		goto end;

	private_key_attrs[1].pValue = unique_id;
	private_key_attrs[1].ulValueLen = unique_id_len;

	TEST_OUT("Find ECDSA private key\n");
	ret = pfunc->C_FindObjectsInit(sess, private_key_attrs,
				       ARRAY_SIZE(private_key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hprivkey, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	if (!is_seco_subsystem()) {
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
		ret = pfunc->C_Sign(sess, msg, msg_len, signature,
				    &signature_len);
		if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Sign"))
			goto end;

		/* Realloc signature buffer with new signature length */
		signature = realloc(signature, signature_len);
		if (CHECK_EXPECTED(signature, "Allocation error"))
			goto end;

		TEST_OUT("Sign message\n");
		ret = pfunc->C_Sign(sess, msg, msg_len, signature,
				    &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_Sign"))
			goto end;

		TEST_OUT("Initialize verify operation\n");
		ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
			goto end;

		TEST_OUT("Verify signature\n");
		ret = pfunc->C_Verify(sess, msg, msg_len, signature,
				      signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_Verify"))
			goto end;

	} else {
		TEST_OUT("Get key attributes not supported\n");
	}

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

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	if (psa_id)
		psa_destroy_key(psa_id);

	if (signature)
		free(signature);

	if (unique_id)
		free(unique_id);

	SUBTEST_END(status);
	return status;
}

static int sign_verify_rsa_pkcs(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_generate_key_args genkey_args = { 0 };
	struct smw_delete_key_args delkey_args = { 0 };
	struct smw_key_attributes key_attributes = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	CK_RV ret = CKR_OK;
	CK_BBOOL btrue = CK_TRUE;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA512_RSA_PKCS };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_ULONG nb_match = 0;

	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL_PTR;
	CK_ULONG key_length = 256;
	CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE public_key_attrs[] = {
		{ CKA_CLASS, &public_key_class, sizeof(public_key_class) },
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	CK_ATTRIBUTE private_key_attrs[] = {
		{ CKA_CLASS, &private_key_class, sizeof(private_key_class) },
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, sign_verify_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Set key attributes */
	if (SET_OVERFLOW(BYTES_TO_BITS(key_length),
			 key_descriptor.security_size))
		goto end;

	key_descriptor.type_name = SMW_KEY_TYPE_NAME_RSA;
	key_attributes.attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;
	key_attributes.permitted_algo =
		SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(SMW_ATTR_MODE_PKCS1_1_5,
						       SMW_ATTR_HASH_SHA512, 0);
	key_attributes.usage_flags =
		SMW_ATTR_USAGE_SIGN_MESSAGE | SMW_ATTR_USAGE_VERIFY_MESSAGE;

	genkey_args.key_descriptor = &key_descriptor;
	genkey_args.key_attributes = &key_attributes;
	delkey_args.key_descriptor = &key_descriptor;

	smw_status = smw_generate_key(&genkey_args);
	if (smw_status != SMW_STATUS_OK &&
	    smw_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, public_key_class,
				 key_descriptor.id);
	if (ret != CKR_BUFFER_TOO_SMALL)
		goto end;

	unique_id = calloc(1, unique_id_len);
	if (!unique_id)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, public_key_class,
				 key_descriptor.id);
	if (ret != CKR_OK)
		goto end;

	public_key_attrs[1].pValue = unique_id;
	public_key_attrs[1].ulValueLen = unique_id_len;

	TEST_OUT("Find RSA public key\n");
	ret = pfunc->C_FindObjectsInit(sess, public_key_attrs,
				       ARRAY_SIZE(public_key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hpubkey, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	free(unique_id);
	unique_id = NULL_PTR;
	unique_id_len = 0;

	ret = util_set_unique_id(unique_id, &unique_id_len, private_key_class,
				 key_descriptor.id);
	if (ret != CKR_BUFFER_TOO_SMALL)
		goto end;

	unique_id = calloc(1, unique_id_len);
	if (!unique_id)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, private_key_class,
				 key_descriptor.id);
	if (ret != CKR_OK)
		goto end;

	private_key_attrs[1].pValue = unique_id;
	private_key_attrs[1].ulValueLen = unique_id_len;

	TEST_OUT("Find RSA private key\n");
	ret = pfunc->C_FindObjectsInit(sess, private_key_attrs,
				       ARRAY_SIZE(private_key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hprivkey, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	if (!is_seco_subsystem()) {
		TEST_OUT("Initialize sign operation\n");
		ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
		if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
			goto end;

		TEST_OUT("Get signature length (use NULL signature buffer)\n");
		ret = pfunc->C_Sign(sess, NULL_PTR, 0, signature,
				    &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_Sign"))
			goto end;

		signature = malloc(signature_len);
		if (CHECK_EXPECTED(signature, "Allocation error"))
			goto end;

		TEST_OUT("Sign message\n");
		ret = pfunc->C_Sign(sess, msg, msg_len, signature,
				    &signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_Sign"))
			goto end;

		TEST_OUT("Initialize verify operation\n");
		ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
		if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
			goto end;

		TEST_OUT("Verify signature\n");
		ret = pfunc->C_Verify(sess, msg, msg_len, signature,
				      signature_len);
		if (CHECK_CK_RV(CKR_OK, "C_Verify"))
			goto end;
	} else {
		TEST_OUT("Get key attributes not supported\n");
	}

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

	/* Destroy the key */
	if (key_descriptor.id)
		smw_delete_key(&delkey_args);

	if (signature)
		free(signature);

	if (unique_id)
		free(unique_id);

	SUBTEST_END(status);
	return status;
}

static int data_storage_store(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_storage_uid_t data_id = 0xCAFE;

	CK_RV ret = CKR_OK;
	CK_BBOOL btrue = CK_TRUE;
	CK_SESSION_HANDLE sess = 0;
	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL_PTR;
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BYTE data[] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE retrieved_data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	CK_ATTRIBUTE data_template[] = {
		{ CKA_UNIQUE_ID, unique_id, sizeof(unique_id) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE retrieve_template[] = { { CKA_VALUE, retrieved_data,
					       sizeof(retrieved_data) } };
	CK_ULONG nb_match = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	/* Initialize PSA Crypto */
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS)
		goto end;

	psa_status =
		psa_its_set(data_id, sizeof(data), data, PSA_STORAGE_FLAG_NONE);
	if (psa_status != PSA_SUCCESS)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, data_class,
				 data_id);
	if (ret != CKR_BUFFER_TOO_SMALL)
		goto end;

	unique_id = calloc(1, unique_id_len);
	if (!unique_id)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, data_class,
				 data_id);
	if (ret != CKR_OK)
		goto end;

	data_template[0].pValue = unique_id;
	data_template[0].ulValueLen = unique_id_len;

	TEST_OUT("Find Data\n");
	ret = pfunc->C_FindObjectsInit(sess, data_template,
				       ARRAY_SIZE(data_template));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hdata, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	TEST_OUT("Retrieve Data\n");
	ret = pfunc->C_GetAttributeValue(sess, hdata, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (!util_compare_buffers(data, sizeof(data),
				  retrieve_template[0].pValue,
				  retrieve_template[0].ulValueLen)) {
		TEST_OUT("Retrieved Data is not the same\n");
		goto end;
	}

	TEST_OUT("Destroy Data\n");
	ret = pfunc->C_DestroyObject(sess, hdata);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (data_id)
		psa_its_remove(data_id);

	if (unique_id)
		free(unique_id);

	SUBTEST_END(status);
	return status;
}

static int object_attribute_cipher_key(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t psa_id = PSA_KEY_ID_NULL;
	psa_key_type_t key_type = PSA_KEY_TYPE_AES;
	psa_algorithm_t aes_algo_type = PSA_ALG_CBC_NO_PADDING;

	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_object_descriptor descriptor = { 0 };

	CK_RV ret = CKR_OK;
	CK_BBOOL btrue = CK_TRUE;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_CHAR key_label[] = "my key";

	/* AES - 256 bits key length */
	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL_PTR;
	CK_ULONG key_length = 32;
	CK_ULONG nb_match = 0;

	CK_ATTRIBUTE aes_key_attrs[] = {
		{ CKA_UNIQUE_ID, unique_id, sizeof(unique_id) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	CK_ATTRIBUTE keyAttrLabel[] = {
		{ CKA_LABEL, &key_label, sizeof(key_label) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Initialize PSA Crypto */
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS)
		goto end;

	TEST_OUT("Generate Key Secret key\n");
	/* Set key attributes */
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_type(&attributes, key_type);
	psa_set_key_bits(&attributes, BYTES_TO_BITS(key_length));
	psa_set_key_algorithm(&attributes, aes_algo_type);

	/* Generate the key */
	psa_status = psa_generate_key(&attributes, &psa_id);
	if (psa_status != PSA_SUCCESS)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, key_class, psa_id);
	if (ret != CKR_BUFFER_TOO_SMALL)
		goto end;

	unique_id = calloc(1, unique_id_len);
	if (!unique_id)
		goto end;

	ret = util_set_unique_id(unique_id, &unique_id_len, key_class, psa_id);
	if (ret != CKR_OK)
		goto end;

	aes_key_attrs[0].pValue = unique_id;
	aes_key_attrs[0].ulValueLen = unique_id_len;

	TEST_OUT("Key secret generated #%lu\n", hkey);
	ret = pfunc->C_FindObjectsInit(sess, aes_key_attrs,
				       ARRAY_SIZE(aes_key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hkey, 1, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	TEST_OUT("Update label attribute\n");
	ret = pfunc->C_SetAttributeValue(sess, hkey, keyAttrLabel,
					 ARRAY_SIZE(keyAttrLabel));
	if (CHECK_CK_RV(CKR_OK, "C_SetAttributeValue"))
		goto end;

	descriptor.id = psa_id;
	smw_status = smw_find_object_db(&descriptor);
	if (smw_status != SMW_STATUS_OK)
		goto end;

	if (!util_compare_buffers(key_label, strlen((char *)key_label),
				  (unsigned char *)descriptor.label,
				  strlen(descriptor.label))) {
		TEST_OUT("Retrieved Label is not correct\n");
		goto end;
	}

	TEST_OUT("Key Destroy #%lu\n", hkey);
	ret = pfunc->C_DestroyObject(sess, hkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	if (psa_id)
		psa_destroy_key(psa_id);

	if (unique_id)
		free(unique_id);

	SUBTEST_END(status);
	return status;
}

static int find_all_objects(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t psa_id = PSA_KEY_ID_NULL;
	psa_key_type_t key_type = PSA_KEY_TYPE_AES;
	psa_algorithm_t aes_algo_type = PSA_ALG_CBC_NO_PADDING;
	unsigned int descriptor_id = 0;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	/* Maximum unique id rfc2279 len */
	CK_BYTE key_id[(sizeof(CK_OBJECT_CLASS) + sizeof(uint32_t)) * 2] = { 0 };
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;

	/* AES - 256 bits key length */
	CK_ULONG key_length = 32;
	CK_ULONG nb_match = 0;

	CK_ATTRIBUTE retrieve_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_UNIQUE_ID, &key_id, sizeof(key_id) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	/* Initialize PSA Crypto */
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS)
		goto end;

	TEST_OUT("Generate Key Secret key\n");
	/* Set key attributes */
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_type(&attributes, key_type);
	psa_set_key_bits(&attributes, BYTES_TO_BITS(key_length));
	psa_set_key_algorithm(&attributes, aes_algo_type);

	/* Generate the key */
	psa_status = psa_generate_key(&attributes, &psa_id);
	if (psa_status != PSA_SUCCESS)
		goto end;

	TEST_OUT("Key secret generated #%lu\n", hkey);

	ret = pfunc->C_FindObjectsInit(sess, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	do {
		ret = pfunc->C_FindObjects(sess, &hkey, 1, &nb_match);
		if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
			goto end;

		if (CHECK_EXPECTED(nb_match == 1,
				   "Got %lu but expected one object", nb_match))
			goto end;

		TEST_OUT("Retrieve Key ID\n");

		retrieve_template[1].ulValueLen = sizeof(key_id);
		ret = pfunc->C_GetAttributeValue(sess, hkey, retrieve_template,
						 ARRAY_SIZE(retrieve_template));

		/* For profile objects CKA_UNIQUE_ID attribute is not set.
		 * Hence, continue finding the next object if CKR_ATTRIBUTE_TYPE_INVALID
		 * is returned.
		 */
		if (obj_class == CKO_PROFILE &&
		    ret == CKR_ATTRIBUTE_TYPE_INVALID)
			continue;

		if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
			goto end;

		ret = util_get_object_id(key_id, sizeof(key_id),
					 &descriptor_id);
		if (ret != CKR_OK)
			goto end;

		TEST_OUT("Retrieve ID %d\n", descriptor_id);
	} while (descriptor_id != psa_id);

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hkey);
	ret = pfunc->C_DestroyObject(sess, hkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	if (psa_id)
		psa_destroy_key(psa_id);

	SUBTEST_END(status);
	return status;
}

static int generate_cipher_key(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	CK_ULONG key_len = 16;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_BBOOL btrue = CK_TRUE;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_ECB };

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ULONG nb_keys_match = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), &hkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	util_close_session(pfunc, &sess);

	ret = pfunc->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		goto end;

	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	ret = pfunc->C_FindObjectsInit(sess, match_attrs,
				       ARRAY_SIZE(match_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hkey, 1, &nb_keys_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_keys_match == 1,
			   "Got %lu but expected %d objects", nb_keys_match, 1))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hkey);
	ret = pfunc->C_DestroyObject(sess, hkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int generate_cipher_key_user_id(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	CK_BYTE key_id[] = { 0xf0, 0x0d };
	CK_ULONG key_len = 16;
	CK_BBOOL btrue = CK_TRUE;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_ECB };

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ULONG nb_keys_match = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
	};

	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), &hkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	util_close_session(pfunc, &sess);

	ret = pfunc->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		goto end;

	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	ret = pfunc->C_FindObjectsInit(sess, match_attrs,
				       ARRAY_SIZE(match_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hkey, 1, &nb_keys_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_keys_match == 1,
			   "Got %lu but expected %d objects", nb_keys_match, 1))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hkey);
	ret = pfunc->C_DestroyObject(sess, hkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int generate_transient_cipher_key(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	CK_BYTE key_id[] = { 0xf0, 0x0d };
	CK_ULONG key_len = 16;
	CK_BBOOL btrue = CK_TRUE;
	CK_BBOOL bfalse = CK_FALSE;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_ECB };

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &bfalse, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ULONG nb_keys_match = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_TOKEN, &bfalse, sizeof(CK_BBOOL) },
	};

	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), &hkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	util_close_session(pfunc, &sess);

	ret = pfunc->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		goto end;

	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	ret = pfunc->C_FindObjectsInit(sess, match_attrs,
				       ARRAY_SIZE(match_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &hkey, 1, &nb_keys_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_keys_match == 0,
			   "Got %lu but expected %d objects", nb_keys_match, 1))
		goto end;

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int get_secret_key_size(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM genmech = { .mechanism = CKM_AES_KEY_GEN };
	CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
	CK_ULONG key_len = 16;
	CK_ULONG size = 0;
	CK_BBOOL btrue = CK_TRUE;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_AES_ECB };

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &btrue, sizeof(btrue) },
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

	ret = pfunc->C_GenerateKey(sess, &genmech, key_attrs,
				   ARRAY_SIZE(key_attrs), &hkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKey"))
		goto end;

	TEST_OUT("Get key size #%lu\n", hkey);
	ret = pfunc->C_GetObjectSize(sess, hkey, &size);
	if (CHECK_CK_RV(CKR_OK, "C_GetObjectSize"))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hkey);
	ret = pfunc->C_DestroyObject(sess, hkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	if (CHECK_EXPECTED(key_len == size, "Got %lu but expected %lu size",
			   size, key_len))
		goto end;

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int get_key_pair_size(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_ULONG pubkey_size = 0;
	CK_ULONG privkey_size = 0;
	const struct asn1_ec_curve *curve = &ec_curves[SECP_R1_192];
	CK_ULONG key_size = BITS_TO_BYTES_SIZE((size_t)curve->security_size);
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_BBOOL bverify = CK_TRUE;
	CK_BBOOL bsign = CK_TRUE;
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA224,
						 CKM_ECDSA_SHA256 };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &bverify, sizeof(bverify) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &bsign, sizeof(bsign) },
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

	TEST_OUT("Generate Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0], curve),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Keypair generated by curve name pub=#%lu priv=#%lu\n",
		 hpubkey, hprivkey);

	TEST_OUT("Get public key size #%lu\n", hpubkey);
	ret = pfunc->C_GetObjectSize(sess, hpubkey, &pubkey_size);
	if (CHECK_CK_RV(CKR_OK, "C_GetObjectSize"))
		goto end;

	TEST_OUT("Get private key size #%lu\n", hprivkey);
	ret = pfunc->C_GetObjectSize(sess, hprivkey, &privkey_size);
	if (CHECK_CK_RV(CKR_OK, "C_GetObjectSize"))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hpubkey);
	ret = pfunc->C_DestroyObject(sess, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Key Destroy #%lu\n", hprivkey);
	ret = pfunc->C_DestroyObject(sess, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	if (CHECK_EXPECTED(key_size == pubkey_size,
			   "Got %lu but expected %lu size", pubkey_size,
			   key_size))
		goto end;

	if (CHECK_EXPECTED(key_size == privkey_size,
			   "Got %lu but expected %lu size", privkey_size,
			   key_size))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int data_storage_destroy(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_object_descriptor descriptor = { 0 };

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE data_id[sizeof(CK_OBJECT_CLASS) + sizeof(uint32_t) + 1] = { 0 };
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BYTE data[] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BBOOL btrue = CK_TRUE;
	CK_UTF8CHAR label[] = "Data";

	CK_ATTRIBUTE dataTemplate[] = {
		{ CKA_CLASS, &data_class, sizeof(data_class) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, &data, sizeof(data) },
		{ CKA_TOKEN, &btrue, sizeof(CK_BBOOL) }
	};
	CK_ATTRIBUTE retrieve_template[] = { { CKA_UNIQUE_ID, &data_id,
					       sizeof(data_id) } };
	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create Secret key\n");
	ret = pfunc->C_CreateObject(sess, dataTemplate,
				    ARRAY_SIZE(dataTemplate), &hdata);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Data created #%lu\n", hdata);

	TEST_OUT("Retrieve Data ID\n");
	ret = pfunc->C_GetAttributeValue(sess, hdata, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	ret = util_get_object_id(data_id, sizeof(data_id), &descriptor.id);
	if (ret != CKR_OK)
		goto end;

	smw_status = smw_find_object_db(&descriptor);
	if (smw_status != SMW_STATUS_OK)
		goto end;

	if (!util_compare_buffers(label, strlen((char *)label),
				  (unsigned char *)descriptor.label,
				  strlen(descriptor.label))) {
		TEST_OUT("Retrieved Label is not correct\n");
		goto end;
	}

	TEST_OUT("Destroy Data\n");
	ret = pfunc->C_DestroyObject(sess, hdata);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	util_close_session(pfunc, &sess);

	ret = pfunc->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		goto end;

	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Check database\n");
	smw_status = smw_find_object_db(&descriptor);
	if (smw_status != SMW_STATUS_UNKNOWN_ID)
		goto end;

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int get_data_size(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hdata = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BBOOL token = CK_TRUE;
	CK_UTF8CHAR label[] = "Data";
	CK_ULONG size = 0;
	CK_BYTE data[] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_ATTRIBUTE data_template[] = {
		{ CKA_CLASS, &data_class, sizeof(data_class) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, data, sizeof(data) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Create %sData\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(sess, data_template,
				    ARRAY_SIZE(data_template), &hdata);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Get data size #%lu\n", hdata);
	ret = pfunc->C_GetObjectSize(sess, hdata, &size);
	if (CHECK_CK_RV(CKR_OK, "C_GetObjectSize"))
		goto end;

	TEST_OUT("Destroy %sData\n", token ? "Token " : "");
	ret = pfunc->C_DestroyObject(sess, hdata);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	if (CHECK_EXPECTED(sizeof(data) == size,
			   "Got %lu but expected %lu size", size, sizeof(data)))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_objects(void *lib_hdl, CK_VOID_PTR pfunc)
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

	if (encrypt_decrypt_aes(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_ecdsa(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_rsa_pkcs(pfunc) == TEST_FAIL)
		goto end;

	if (data_storage_store(pfunc) == TEST_FAIL)
		goto end;

	if (object_attribute_cipher_key(pfunc) == TEST_FAIL)
		goto end;

	if (find_all_objects(pfunc) == TEST_FAIL)
		goto end;

	if (generate_cipher_key(pfunc) == TEST_FAIL)
		goto end;

	if (generate_cipher_key_user_id(pfunc) == TEST_FAIL)
		goto end;

	if (generate_transient_cipher_key(pfunc) == TEST_FAIL)
		goto end;

	if (get_secret_key_size(pfunc) == TEST_FAIL)
		goto end;

	if (get_key_pair_size(pfunc) == TEST_FAIL)
		goto end;

	/*
	 * Delete data not supported by SECO
	 */
	if (!is_seco_subsystem()) {
		if (get_data_size(pfunc) == TEST_FAIL)
			goto end;

		status = data_storage_destroy(pfunc);
	} else {
		status = TEST_PASS;
	}

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
