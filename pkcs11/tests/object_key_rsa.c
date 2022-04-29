// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util_session.h"

/*
 * CAVS 16.1 -
 * "https://csrc.nist.gov/CSRC/media/Projects/
 * Cryptographic-Algorithm-Validation-Program/documents/components/
 * RSA2SP1testvectors.zip"
 *
 * RSA Key Modulus 2048 - COUNT=0
 *
 */
static const CK_BYTE rsa_modulus[] = {
	0xba, 0xd4, 0x7a, 0x84, 0xc1, 0x78, 0x2e, 0x4d, 0xbd, 0xd9, 0x13, 0xf2,
	0xa2, 0x61, 0xfc, 0x8b, 0x65, 0x83, 0x84, 0x12, 0xc6, 0xe4, 0x5a, 0x20,
	0x68, 0xed, 0x6d, 0x7f, 0x16, 0xe9, 0xcd, 0xf4, 0x46, 0x2b, 0x39, 0x11,
	0x95, 0x63, 0xca, 0xfb, 0x74, 0xb9, 0xcb, 0xf2, 0x5c, 0xfd, 0x54, 0x4b,
	0xda, 0xe2, 0x3b, 0xff, 0x0e, 0xbe, 0x7f, 0x64, 0x41, 0x04, 0x2b, 0x7e,
	0x10, 0x9b, 0x9a, 0x8a, 0xfa, 0xa0, 0x56, 0x82, 0x1e, 0xf8, 0xef, 0xaa,
	0xb2, 0x19, 0xd2, 0x1d, 0x67, 0x63, 0x48, 0x47, 0x85, 0x62, 0x2d, 0x91,
	0x8d, 0x39, 0x5a, 0x2a, 0x31, 0xf2, 0xec, 0xe8, 0x38, 0x5a, 0x81, 0x31,
	0xe5, 0xff, 0x14, 0x33, 0x14, 0xa8, 0x2e, 0x21, 0xaf, 0xd7, 0x13, 0xba,
	0xe8, 0x17, 0xcc, 0x0e, 0xe3, 0x51, 0x4d, 0x48, 0x39, 0x00, 0x7c, 0xcb,
	0x55, 0xd6, 0x84, 0x09, 0xc9, 0x7a, 0x18, 0xab, 0x62, 0xfa, 0x6f, 0x9f,
	0x89, 0xb3, 0xf9, 0x4a, 0x27, 0x77, 0xc4, 0x7d, 0x61, 0x36, 0x77, 0x5a,
	0x56, 0xa9, 0xa0, 0x12, 0x7f, 0x68, 0x24, 0x70, 0xbe, 0xf8, 0x31, 0xfb,
	0xec, 0x4b, 0xcd, 0x7b, 0x50, 0x95, 0xa7, 0x82, 0x3f, 0xd7, 0x07, 0x45,
	0xd3, 0x7d, 0x1b, 0xf7, 0x2b, 0x63, 0xc4, 0xb1, 0xb4, 0xa3, 0xd0, 0x58,
	0x1e, 0x74, 0xbf, 0x9a, 0xde, 0x93, 0xcc, 0x46, 0x14, 0x86, 0x17, 0x55,
	0x39, 0x31, 0xa7, 0x9d, 0x92, 0xe9, 0xe4, 0x88, 0xef, 0x47, 0x22, 0x3e,
	0xe6, 0xf6, 0xc0, 0x61, 0x88, 0x4b, 0x13, 0xc9, 0x06, 0x5b, 0x59, 0x11,
	0x39, 0xde, 0x13, 0xc1, 0xea, 0x29, 0x27, 0x49, 0x1e, 0xd0, 0x0f, 0xb7,
	0x93, 0xcd, 0x68, 0xf4, 0x63, 0xf5, 0xf6, 0x4b, 0xaa, 0x53, 0x91, 0x6b,
	0x46, 0xc8, 0x18, 0xab, 0x99, 0x70, 0x65, 0x57, 0xa1, 0xc2, 0xd5, 0x0d,
	0x23, 0x25, 0x77, 0xd1,
};

const CK_BYTE rsa_pub_exp[] = { 0x01, 0x00, 0x01 };

const CK_BYTE rsa_priv_exp[] = {
	0x40, 0xd6, 0x0f, 0x24, 0xb6, 0x1d, 0x76, 0x78, 0x3d, 0x3b, 0xb1, 0xdc,
	0x00, 0xb5, 0x5f, 0x96, 0xa2, 0xa6, 0x86, 0xf5, 0x9b, 0x37, 0x50, 0xfd,
	0xb1, 0x5c, 0x40, 0x25, 0x1c, 0x37, 0x0c, 0x65, 0xca, 0xda, 0x22, 0x26,
	0x73, 0x81, 0x1b, 0xc6, 0xb3, 0x05, 0xed, 0x7c, 0x90, 0xff, 0xcb, 0x3a,
	0xbd, 0xdd, 0xc8, 0x33, 0x66, 0x12, 0xff, 0x13, 0xb4, 0x2a, 0x75, 0xcb,
	0x7c, 0x88, 0xfb, 0x93, 0x62, 0x91, 0xb5, 0x23, 0xd8, 0x0a, 0xcc, 0xe5,
	0xa0, 0x84, 0x2c, 0x72, 0x4e, 0xd8, 0x5a, 0x13, 0x93, 0xfa, 0xf3, 0xd4,
	0x70, 0xbd, 0xa8, 0x08, 0x3f, 0xa8, 0x4d, 0xc5, 0xf3, 0x14, 0x99, 0x84,
	0x4f, 0x0c, 0x7c, 0x1e, 0x93, 0xfb, 0x1f, 0x73, 0x4a, 0x5a, 0x29, 0xfb,
	0x31, 0xa3, 0x5c, 0x8a, 0x08, 0x22, 0x45, 0x5f, 0x1c, 0x85, 0x0a, 0x49,
	0xe8, 0x62, 0x97, 0x14, 0xec, 0x6a, 0x26, 0x57, 0xef, 0xe7, 0x5e, 0xc1,
	0xca, 0x6e, 0x62, 0xf9, 0xa3, 0x75, 0x6c, 0x9b, 0x20, 0xb4, 0x85, 0x5b,
	0xdc, 0x9a, 0x3a, 0xb5, 0x8c, 0x43, 0xd8, 0xaf, 0x85, 0xb8, 0x37, 0xa7,
	0xfd, 0x15, 0xaa, 0x11, 0x49, 0xc1, 0x19, 0xcf, 0xe9, 0x60, 0xc0, 0x5a,
	0x9d, 0x4c, 0xea, 0x69, 0xc9, 0xfb, 0x6a, 0x89, 0x71, 0x45, 0x67, 0x48,
	0x82, 0xbf, 0x57, 0x24, 0x1d, 0x77, 0xc0, 0x54, 0xdc, 0x4c, 0x94, 0xe8,
	0x34, 0x9d, 0x37, 0x62, 0x96, 0x13, 0x7e, 0xb4, 0x21, 0x68, 0x61, 0x59,
	0xcb, 0x87, 0x8d, 0x15, 0xd1, 0x71, 0xed, 0xa8, 0x69, 0x28, 0x34, 0xaf,
	0xc8, 0x71, 0x98, 0x8f, 0x20, 0x3f, 0xc8, 0x22, 0xc5, 0xdc, 0xee, 0x7f,
	0x6c, 0x48, 0xdf, 0x66, 0x3e, 0xa3, 0xdc, 0x75, 0x5e, 0x7d, 0xc0, 0x6a,
	0xeb, 0xd4, 0x1d, 0x05, 0xf1, 0xca, 0x28, 0x91, 0xe2, 0x67, 0x97, 0x83,
	0x24, 0x4d, 0x06, 0x8f,
};

static int object_rsa_key_public(CK_FUNCTION_LIST_PTR pfunc, CK_BBOOL token,
				 CK_BBOOL bverify)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_RSA;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_RSA_PKCS,
						 CKM_SHA256_RSA_PKCS };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VERIFY, &bverify, sizeof(bverify) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_MODULUS, (CK_BYTE_PTR)rsa_modulus, sizeof(rsa_modulus) },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exp,
		  sizeof(rsa_pub_exp) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Create RSA %sKey Public\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);

	if (bverify) {
		if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
			goto end;

		TEST_OUT("RSA Key public created #%lu\n", hkey);

		TEST_OUT("Key Destroy #%lu\n", hkey);
		ret = pfunc->C_DestroyObject(sess, hkey);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			goto end;
	} else {
		if (CHECK_CK_RV(CKR_DEVICE_ERROR, "C_CreateObject"))
			goto end;
	}

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_rsa_key_private(CK_FUNCTION_LIST_PTR pfunc, CK_BBOOL token,
				  CK_BBOOL bsign)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hkey;
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_RSA;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_RSA_PKCS_PSS,
						 CKM_SHA256_RSA_PKCS_PSS };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_SIGN, &bsign, sizeof(bsign) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_MODULUS, (CK_BYTE_PTR)rsa_modulus, sizeof(rsa_modulus) },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exp,
		  sizeof(rsa_pub_exp) },
		{ CKA_PRIVATE_EXPONENT, (CK_BYTE_PTR)rsa_priv_exp,
		  sizeof(rsa_priv_exp) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START(status);

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Create RSA %sKey Private\n", token ? "Token " : "");
	ret = pfunc->C_CreateObject(sess, keyTemplate, ARRAY_SIZE(keyTemplate),
				    &hkey);

	if (bsign) {
		if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
			goto end;

		TEST_OUT("RSA Key private created #%lu\n", hkey);
	} else {
		if (CHECK_CK_RV(CKR_DEVICE_ERROR, "C_CreateObject"))
			goto end;
	}

	status = TEST_PASS;
end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_generate_rsa_keypair(CK_FUNCTION_LIST_PTR pfunc,
				       CK_BBOOL token, bool with_pub_exp)
{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hpubkey;
	CK_OBJECT_HANDLE hprivkey;
	CK_MECHANISM genmech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_ULONG modulus_bits = 0;
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_RSA_PKCS_PSS,
						 CKM_SHA256_RSA_PKCS_PSS };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_VERIFY, &btrue, sizeof(btrue) },
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exp,
		  sizeof(rsa_pub_exp) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ULONG nb_pubkey_attrs = 0;
	CK_ATTRIBUTE *privkey_attrs = NULL;
	CK_ULONG nb_privkey_attrs = 0;
	CK_ATTRIBUTE privkey_token[] = {
		{ CKA_SIGN, &btrue, sizeof(btrue) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START(status);

	modulus_bits = sizeof(rsa_modulus) * 8;

	if (token) {
		privkey_attrs = privkey_token;
		nb_privkey_attrs = ARRAY_SIZE(privkey_token);
	}

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (with_pub_exp) {
		TEST_OUT("Generate RSA %sKeypair with Public Exponent\n",
			 token ? "Token " : "");
		nb_pubkey_attrs = ARRAY_SIZE(pubkey_attrs);
	} else {
		TEST_OUT("Generate RSA %sKeypair without Public Exponent\n",
			 token ? "Token " : "");
		nb_pubkey_attrs = ARRAY_SIZE(pubkey_attrs) - 1;
	}
	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       nb_pubkey_attrs, privkey_attrs,
				       nb_privkey_attrs, &hpubkey, &hprivkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("RSA Keypair generated pub=#%lu priv=#%lu\n", hpubkey,
		 hprivkey);

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_rsa_keypair_usage(CK_FUNCTION_LIST_PTR pfunc, CK_BBOOL token)

{
	int status;

	CK_RV ret;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE hpubkey;
	CK_OBJECT_HANDLE hprivkey;
	CK_MECHANISM genmech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_ULONG modulus_bits = 0;
	CK_BBOOL bverify = CK_FALSE;
	CK_BBOOL bsign = CK_FALSE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_RSA_PKCS_PSS,
						 CKM_SHA384_RSA_PKCS };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_VERIFY, &bverify, sizeof(bverify) },
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exp,
		  sizeof(rsa_pub_exp) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &bsign, sizeof(bsign) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START(status);

	modulus_bits = sizeof(rsa_modulus) * 8;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate RSA %sKeypair with no usage\n",
		 token ? "Token " : "");
	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);

	if (CHECK_CK_RV(CKR_DEVICE_ERROR, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Generate RSA %sKeypair with only sign usage\n",
		 token ? "Token " : "");

	bsign = CK_TRUE;

	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Generate RSA %sKeypair with only verify usage\n",
		 token ? "Token " : "");

	bsign = CK_FALSE;
	bverify = CK_TRUE;

	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);

	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}
void tests_pkcs11_object_key_rsa(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	(void)lib_hdl;
	int status;

	CK_RV ret;
	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START(status);

	ret = pfunc->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (object_rsa_key_public(pfunc, false, true) == TEST_FAIL)
		goto end;

	if (object_rsa_key_public(pfunc, false, false) == TEST_FAIL)
		goto end;

	if (object_rsa_key_private(pfunc, false, true) == TEST_FAIL)
		goto end;

	if (object_rsa_key_private(pfunc, false, false) == TEST_FAIL)
		goto end;

	if (object_generate_rsa_keypair(pfunc, false, false) == TEST_FAIL)
		goto end;

	if (object_generate_rsa_keypair(pfunc, false, true) == TEST_FAIL)
		goto end;

	if (object_rsa_keypair_usage(pfunc, false) == TEST_FAIL)
		goto end;

	if (object_rsa_key_public(pfunc, true, true) == TEST_FAIL)
		goto end;

	if (object_rsa_key_public(pfunc, true, false) == TEST_FAIL)
		goto end;

	if (object_rsa_key_private(pfunc, true, true) == TEST_FAIL)
		goto end;

	if (object_rsa_key_private(pfunc, true, false) == TEST_FAIL)
		goto end;

	if (object_generate_rsa_keypair(pfunc, true, false) == TEST_FAIL)
		goto end;

	if (object_generate_rsa_keypair(pfunc, true, true) == TEST_FAIL)
		goto end;

	status = object_rsa_keypair_usage(pfunc, true);

end:
	ret = pfunc->C_Finalize(NULL);

	TEST_END(status);
}
