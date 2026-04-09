// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "os_mutex.h"
#include "util.h"
#include "util_lib.h"
#include "util_session.h"
#include "util.h"

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

static CK_BYTE msg_sha256[] = {
	0xd1, 0x5f, 0xa5, 0xd0, 0xd1, 0x95, 0xca, 0xff, 0x1d, 0x67, 0xc8,
	0xcd, 0x5a, 0xc0, 0xc5, 0x14, 0xcd, 0xdf, 0xdc, 0x54, 0x3f, 0xd0,
	0xa0, 0x79, 0x2d, 0x85, 0x80, 0x9e, 0xb0, 0xd7, 0x7d, 0x1a
};

static CK_ULONG msg_sha256_len = 32;

static CK_BYTE msg_sha384[] = {
	0xb8, 0xe0, 0xcd, 0x2f, 0x4a, 0x71, 0x77, 0x3b, 0x68, 0x82, 0xb9, 0x46,
	0xc1, 0x08, 0x56, 0x82, 0xd2, 0x88, 0xea, 0x72, 0x02, 0x5d, 0x9b, 0x63,
	0xe9, 0x7b, 0x56, 0xc9, 0x7a, 0x38, 0x87, 0x68, 0x70, 0x78, 0xdc, 0xc4,
	0x52, 0x16, 0x72, 0xfe, 0x5b, 0x96, 0x82, 0x1e, 0x22, 0x94, 0x52, 0xd2
};

static CK_ULONG msg_sha384_len = 48;

static CK_BYTE msg_sha512[] = {
	0xe6, 0x7e, 0xf4, 0x68, 0x5e, 0x8e, 0x06, 0x28, 0x20, 0x86, 0x9e,
	0xd8, 0x32, 0x56, 0xcf, 0xb5, 0xeb, 0x06, 0xb4, 0xa7, 0xf5, 0xa7,
	0x00, 0x56, 0x41, 0x2e, 0x9a, 0xaf, 0x1f, 0x4f, 0x7c, 0x0e, 0xd7,
	0x60, 0xb2, 0xae, 0xe6, 0x84, 0x5d, 0xe3, 0xd5, 0x38, 0xb4, 0xae,
	0x4e, 0x9c, 0x7f, 0x12, 0x85, 0x56, 0xa6, 0xc8, 0xa5, 0xc7, 0x99,
	0xbf, 0x68, 0x72, 0x69, 0x8d, 0x00, 0x48, 0x42, 0x55
};

static CK_ULONG msg_sha512_len = 64;

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

static const CK_BYTE rsa_pub_exp[] = { 0x01, 0x00, 0x01 };

static const CK_BYTE rsa_priv_exp[] = {
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

static CK_BYTE sha512_signature[] = {
	0x9f, 0x20, 0x96, 0xd9, 0x08, 0xdc, 0x46, 0xba, 0xe9, 0x6e, 0xa6, 0xc2,
	0x02, 0x98, 0xc9, 0x8f, 0xaa, 0x03, 0xb4, 0x9f, 0x62, 0xf6, 0xc0, 0x6a,
	0xac, 0xa7, 0x57, 0x59, 0x5d, 0x4f, 0xa1, 0xde, 0xc1, 0x5c, 0x77, 0xd3,
	0xf4, 0x28, 0x3d, 0xa6, 0x70, 0x34, 0xe2, 0x6c, 0x4f, 0x72, 0xd7, 0xf4,
	0xab, 0x02, 0x41, 0x43, 0xed, 0x43, 0xb7, 0x44, 0x8c, 0x72, 0x8f, 0x9b,
	0xa0, 0x14, 0x2d, 0x52, 0x6b, 0x8b, 0x22, 0x5d, 0x9f, 0xdd, 0xd0, 0x02,
	0xb8, 0x77, 0xfc, 0xba, 0x5d, 0xcc, 0x91, 0xec, 0x51, 0x32, 0x0f, 0x76,
	0x41, 0x42, 0xc9, 0x72, 0xd8, 0xfd, 0xa4, 0x6d, 0xa7, 0x87, 0x41, 0x7a,
	0xe9, 0x3c, 0xc1, 0xe2, 0x7a, 0x83, 0x55, 0x40, 0x0c, 0xb2, 0x3b, 0x69,
	0x9b, 0x29, 0x05, 0xf0, 0x75, 0x67, 0xf2, 0x45, 0x7b, 0xc5, 0x9a, 0x02,
	0xe3, 0x72, 0x27, 0x43, 0x91, 0x7c, 0x67, 0xff, 0x45, 0xd7, 0x05, 0xf8,
	0xd6, 0xc4, 0xe2, 0xb7, 0x9e, 0xd9, 0x96, 0xbd, 0x04, 0x1b, 0x33, 0x28,
	0xd5, 0xc2, 0xd0, 0x79, 0x61, 0x89, 0x3f, 0x73, 0xa1, 0x00, 0x48, 0xc8,
	0x93, 0x29, 0x10, 0x63, 0xf1, 0x62, 0xf6, 0x0d, 0x01, 0x59, 0x1c, 0x1a,
	0x2a, 0x17, 0x99, 0x0c, 0xf9, 0xd3, 0xd1, 0xbe, 0x18, 0xbd, 0x35, 0xc3,
	0x85, 0x4d, 0x40, 0xfb, 0xd8, 0x2a, 0xe3, 0x0b, 0xa0, 0x4a, 0xba, 0x7d,
	0xc4, 0x47, 0x3b, 0xf8, 0xe9, 0x67, 0xe5, 0x9e, 0x16, 0x75, 0x8c, 0xe6,
	0x67, 0x69, 0x3f, 0xf1, 0xa8, 0xf5, 0x84, 0xd0, 0xb4, 0xa7, 0xd8, 0x18,
	0x28, 0x9d, 0x14, 0xc5, 0x30, 0x3e, 0x7b, 0x3c, 0x3e, 0x6b, 0x86, 0xe5,
	0x63, 0x33, 0x60, 0x9e, 0xc9, 0xdd, 0x20, 0x97, 0xc0, 0xe0, 0xcd, 0x0b,
	0x35, 0x3a, 0x17, 0xcb, 0x3a, 0x73, 0x3e, 0x35, 0x06, 0x7a, 0x5a, 0x96,
	0x8f, 0x55, 0x3f, 0xfb
};

static CK_BYTE peer_buffer[] = {
	0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7,
	0x02, 0x70, 0x39, 0x8c, 0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc,
	0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63, 0x56,
	0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c,
	0x13, 0xc5, 0x8d, 0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f,
	0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab
};

static CK_BYTE client_random[] = { 0x2e, 0xf5, 0xf5, 0x95, 0x3a, 0xe3, 0x91,
				   0x8a, 0x6c, 0xef, 0x3d, 0x51, 0x14, 0x06,
				   0xe9, 0xa0, 0x2c, 0x65, 0x26, 0x16, 0xd7,
				   0x8f, 0x68, 0xc7, 0x0f, 0x0e, 0x21, 0x69,
				   0xa7, 0x86, 0x4d, 0xbe };

static CK_BYTE server_random[] = { 0x12, 0xd4, 0xd9, 0x0c, 0x3c, 0x89, 0xce,
				   0x1d, 0x50, 0x2a, 0x6a, 0xa2, 0x43, 0x6c,
				   0xb3, 0x2f, 0xb4, 0x98, 0xb0, 0x94, 0x8f,
				   0x63, 0xa5, 0xd0, 0x5c, 0x41, 0x3c, 0xe4,
				   0xa3, 0x42, 0xeb, 0x8d };

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
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_RSA_PKCS_PSS };
	CK_ATTRIBUTE rsa_pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &rsa_modulus_bits, sizeof(CK_ULONG) },
	};
	CK_BBOOL rsa_sign = CK_TRUE;
	CK_ATTRIBUTE rsa_privkey_attrs[] = {
		{ CKA_SIGN, &rsa_sign, sizeof(CK_BBOOL) },
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

	if (!util_lib_is_mech_supported(pfunc, 0, rsa_key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

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
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA256_RSA_PKCS_PSS };
	CK_BBOOL rsa_verify = CK_TRUE;
	CK_ATTRIBUTE rsa_pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &rsa_modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &rsa_verify, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE rsa_privkey_attrs[] = {
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, rsa_key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

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
	CK_ULONG data_len = 0;
	CK_ULONG sign_len = 0;
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
	CK_ULONG data_len = 0;
	CK_ULONG sign_len = 0;
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
	CK_BBOOL ec_verify = CK_TRUE;
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

	TEST_OUT("Generate EC Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_192]),
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
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp = 0;

	CK_OBJECT_HANDLE hpubkey = 0;
	CK_OBJECT_HANDLE hprivkey = 0;
	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
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

	TEST_OUT("Get output buffer length, msg=NULL\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, msg_len, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Sign"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get output buffer length, msg_len=0\n");
	ret = pfunc->C_Sign(sess, msg, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Sign"))
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
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Sign"))
		goto end;

	TEST_OUT("Get output buffer length, msg=NULL and msg_len=0\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	if (CHECK_EXPECTED(tmp == signature_len, "Got %lu but expected %lu",
			   tmp, signature_len))
		goto end;

	/* Realloc signature buffer with new signature length */
	signature = realloc(signature, signature_len);
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

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	/* Change mechanism, use already hashed message */
	sign_verify_mech.mechanism = CKM_ECDSA;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign message\n");
	ret = pfunc->C_Sign(sess, msg_sha256, msg_sha256_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg_sha256, msg_sha256_len, signature,
			      signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
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

	TEST_OUT("Sign message with signature buffer bigger that needed\n");
	ret = pfunc->C_Sign(sess, msg_sha256, msg_sha256_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Check updated signature buffer length\n");
	if (CHECK_EXPECTED(signature_len == tmp,
			   "Signature length not updated"))
		goto end;

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg_sha256, msg_sha256_len, signature,
			      signature_len);
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

static int sign_verify_rsa_pkcs(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA512_RSA_PKCS };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_ULONG modulus_bits = 2048;
	CK_MECHANISM key_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA512_RSA_PKCS };
	CK_BBOOL sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_BBOOL verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &verify, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_mech.mechanism)) {
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

	TEST_OUT("Get output buffer length, msg=NULL\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, msg_len, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Sign"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get output buffer length, msg_len=0\n");
	ret = pfunc->C_Sign(sess, msg, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Sign"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Get output buffer length, msg=NULL and msg_len=0\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	if (CHECK_EXPECTED(tmp == signature_len, "Got %lu but expected %lu",
			   tmp, signature_len))
		goto end;

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

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
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

static int sign_verify_rsa_pss(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_RSA_PKCS_PSS };
	CK_RSA_PKCS_PSS_PARAMS pss_params = { 0 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_ULONG modulus_bits = 2048;
	CK_MECHANISM key_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA384_RSA_PKCS_PSS };
	CK_BBOOL sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_BBOOL verify = CK_TRUE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_VERIFY, &verify, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_mech.mechanism)) {
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

	TEST_OUT("Get output buffer length, msg=NULL\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, msg_len, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Sign"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get output buffer length, msg_len=0\n");
	ret = pfunc->C_Sign(sess, msg, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Sign"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get signature length (sign with NULL signature buffer)\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Get output buffer length, msg=NULL and msg_len=0\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	if (CHECK_EXPECTED(tmp == signature_len, "Got %lu but expected %lu",
			   tmp, signature_len))
		goto end;

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

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
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

static int sign_verify_eddsa(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_BYTE_PTR payload = NULL_PTR;
	CK_ULONG payload_len = 0;
	CK_ULONG tmp = 0;

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
		  sizeof(key_allowed_mech) },
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
	unsigned int i = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, key_mech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	for (; i < ed_curves_count; i++) {
		TEST_OUT("Generate Edwards Keypair by curve name\n");
		if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
						       &ed_curves[i]),
				   "ASN1 Conversion"))
			goto end;

		ret = pfunc->C_GenerateKeyPair(sess, &key_mech, pubkey_attrs,
					       ARRAY_SIZE(pubkey_attrs),
					       privkey_attrs,
					       ARRAY_SIZE(privkey_attrs),
					       &hpubkey, &hprivkey);
		if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
			goto end;

		for (idx = 0; idx < ARRAY_SIZE(sign_verify_mech); idx++) {
			params = sign_verify_mech[idx].pParameter;

			TEST_OUT("Initialize sign operation\n");
			ret = pfunc->C_SignInit(sess, &sign_verify_mech[idx],
						hprivkey);
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

			tmp = 0;
			TEST_OUT("Get output buffer length, msg=NULL\n");
			ret = pfunc->C_Sign(sess, NULL_PTR, payload_len,
					    NULL_PTR, &tmp);
			if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Sign"))
				goto end;

			TEST_OUT("Initialize sign operation\n");
			ret = pfunc->C_SignInit(sess, &sign_verify_mech[idx],
						hprivkey);
			if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
				goto end;

			TEST_OUT("Get output buffer length, msg_len=0\n");
			ret = pfunc->C_Sign(sess, payload, 0, NULL_PTR, &tmp);
			if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Sign"))
				goto end;

			TEST_OUT("Initialize sign operation\n");
			ret = pfunc->C_SignInit(sess, &sign_verify_mech[idx],
						hprivkey);
			if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
				goto end;

			/* Set a wrong signature length */
			signature_len = 20;
			signature = malloc(signature_len);
			if (CHECK_EXPECTED(signature, "Allocation error"))
				goto end;

			TEST_OUT("Sign message with buffer too small\n");
			ret = pfunc->C_Sign(sess, payload, payload_len,
					    signature, &signature_len);
			if (ret == CKR_FUNCTION_NOT_SUPPORTED) {
				free(signature);
				signature = NULL;
				continue;
			}

			if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Sign"))
				goto end;

			tmp = 0;
			TEST_OUT("Get output length, msg=NULL and msg_len=0\n");
			ret = pfunc->C_Sign(sess, NULL_PTR, 0, NULL_PTR, &tmp);
			if (CHECK_CK_RV(CKR_OK, "C_Sign"))
				goto end;

			if (CHECK_EXPECTED(tmp == signature_len,
					   "Got %lu but expected %lu", tmp,
					   signature_len))
				goto end;

			/* Realloc signature buffer with new signature length */
			signature = realloc(signature, signature_len);
			if (CHECK_EXPECTED(signature, "Allocation error"))
				goto end;

			TEST_OUT("Sign message\n");
			ret = pfunc->C_Sign(sess, payload, payload_len,
					    signature, &signature_len);
			if (CHECK_CK_RV(CKR_OK, "C_Sign"))
				goto end;

			TEST_OUT("Initialize verify operation\n");
			ret = pfunc->C_VerifyInit(sess, &sign_verify_mech[idx],
						  hpubkey);
			if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
				goto end;

			TEST_OUT("Verify signature\n");
			ret = pfunc->C_Verify(sess, payload, payload_len,
					      signature, signature_len);
			if (CHECK_CK_RV(CKR_OK, "C_Verify"))
				goto end;

			free(signature);
			signature = NULL;
		}

		free(pubkey_attrs[0].pValue);
		pubkey_attrs[0].pValue = NULL;
	}

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

static int sign_verify_key_usage(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_ECDSA_SHA256 };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey_sign = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey_sign = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hpubkey_verify = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey_verify = CK_INVALID_HANDLE;

	CK_MECHANISM key_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA_SHA256 };
	CK_BBOOL ec_verify = CK_FALSE;
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_VERIFY, &ec_verify, sizeof(CK_BBOOL) },
	};
	CK_BBOOL ec_sign = CK_TRUE;
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_SIGN, &ec_sign, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	SUBTEST_START();

	if (is_seco_subsystem()) {
		status = TEST_SKIP;
		goto end;
	}

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate signature EC Keypair by curve name\n");
	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_256]),
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
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
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
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
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

static int sign_verify_rsa_pkcs_plaintext_key(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_RSA;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA512_RSA_PKCS };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_SHA512_RSA_PKCS };
	CK_BBOOL bsign = CK_TRUE;
	CK_BBOOL bverify = CK_TRUE;

	CK_ATTRIBUTE private_keyTemplate[] = {
		{ CKA_CLASS, &private_key_class, sizeof(private_key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_SIGN, &bsign, sizeof(bsign) },
		{ CKA_MODULUS, (CK_BYTE_PTR)rsa_modulus, sizeof(rsa_modulus) },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exp,
		  sizeof(rsa_pub_exp) },
		{ CKA_PRIVATE_EXPONENT, (CK_BYTE_PTR)rsa_priv_exp,
		  sizeof(rsa_priv_exp) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_ATTRIBUTE public_keyTemplate[] = {
		{ CKA_CLASS, &public_key_class, sizeof(public_key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VERIFY, &bverify, sizeof(bverify) },
		{ CKA_MODULUS, (CK_BYTE_PTR)rsa_modulus, sizeof(rsa_modulus) },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exp,
		  sizeof(rsa_pub_exp) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
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

	TEST_OUT("Create RSA Key Private\n");
	ret = pfunc->C_CreateObject(sess, private_keyTemplate,
				    ARRAY_SIZE(private_keyTemplate), &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Create RSA Key Public\n");
	ret = pfunc->C_CreateObject(sess, public_keyTemplate,
				    ARRAY_SIZE(public_keyTemplate), &hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
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
	ret = pfunc->C_Sign(sess, msg, msg_len, signature, &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	if (!util_compare_buffers(signature, signature_len, sha512_signature,
				  sizeof(sha512_signature))) {
		TEST_OUT("RSA signature invalid\n");
		goto end;
	}

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech, hpubkey);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
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

static int sign_verify_tls(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_TLS_MAC };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	CK_ULONG tmp = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = {
		CKM_TLS12_MASTER_KEY_DERIVE_DH
	};
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL_PTR, 0 },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) },
	};
	CK_ATTRIBUTE privkey_attrs[] = {
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, &base_key_allowed_mech,
		  sizeof(base_key_allowed_mech) },
	};

	CK_TLS12_MASTER_KEY_DERIVE_PARAMS tls12_master_params = { 0 };
	CK_MECHANISM tls12_master_mech = { CKM_TLS12_MASTER_KEY_DERIVE_DH,
					   (void *)&tls12_master_params,
					   sizeof(tls12_master_params) };

	CK_OBJECT_HANDLE master_hsecretkey = 0;
	CK_MECHANISM_TYPE key_allowed_mech = { CKM_TLS_MAC };
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE secret_key_type = CKK_GENERIC_SECRET;
	CK_ULONG secret_key_len = 32;
	CK_TLS_MAC_PARAMS tls_mac_params = { 0 };

	CK_ATTRIBUTE master_secretkey_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type) },
		{ CKA_VALUE_LEN, &secret_key_len, sizeof(secret_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = {
		CKM_TLS12_MASTER_KEY_DERIVE_DH
	};
	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &secret_key_class, sizeof(secret_key_class) },
		{ CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type) },
		{ CKA_VALUE_LEN, &secret_key_len, sizeof(secret_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech) ||
	    !util_lib_is_mech_supported(pfunc, 0, key_allowed_mech) ||
	    !util_lib_is_mech_supported(pfunc, 0, ecdhe_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &ec_curves[SECP_R1_256]),
			   "ASN1 Conversion"))
		goto end;

	TEST_OUT("Generate a base key\n");
	ret = pfunc->C_GenerateKeyPair(sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       ARRAY_SIZE(privkey_attrs), &hpubkey,
				       &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Set CKM_ECDH1_DERIVE mechanism parameters\n");
	ecdh_params.kdf = CKD_NULL;
	ecdh_params.pSharedData = NULL;
	ecdh_params.ulSharedDataLen = 0;
	ecdh_params.pPublicData = peer_buffer;
	ecdh_params.ulPublicDataLen = ARRAY_SIZE(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_TLS12_MASTER_DERIVE mechanism parameters\n");
	tls12_master_params.prfHashMechanism = CKM_SHA256;
	tls12_master_params.pVersion = NULL;
	tls12_master_params.RandomInfo.pClientRandom = client_random;
	tls12_master_params.RandomInfo.pServerRandom = server_random;
	tls12_master_params.RandomInfo.ulClientRandomLen =
		sizeof(client_random);
	tls12_master_params.RandomInfo.ulServerRandomLen =
		sizeof(server_random);

	ret = pfunc->C_DeriveKey(sess, &tls12_master_mech, ecdhe_key,
				 master_secretkey_template,
				 ARRAY_SIZE(master_secretkey_template),
				 &master_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	tls_mac_params.prfHashMechanism = CKM_SHA256;
	tls_mac_params.ulMacLength = 12;
	tls_mac_params.ulServerOrClient = 1; /* server */
	sign_verify_mech.pParameter = &tls_mac_params;
	sign_verify_mech.ulParameterLen = sizeof(tls_mac_params);

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, master_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	tmp = 0;
	TEST_OUT("Get output buffer length, msg_sha256=NULL\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, msg_sha256_len, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_INVALID, "C_Sign"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, master_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get output buffer length, msg_sha256_len=0\n");
	ret = pfunc->C_Sign(sess, msg_sha256, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_DATA_LEN_RANGE, "C_Sign"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, master_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	/* Set a wrong signature length */
	signature_len = 10;
	signature = malloc(signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign message with signature buffer too small\n");
	ret = pfunc->C_Sign(sess, msg_sha256, msg_sha256_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_Sign"))
		goto end;

	TEST_OUT("Get output buffer length, msg=NULL and msg_len=0\n");
	ret = pfunc->C_Sign(sess, NULL_PTR, 0, NULL_PTR, &tmp);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	if (CHECK_EXPECTED(tmp == signature_len, "Got %lu but expected %lu",
			   tmp, signature_len))
		goto end;

	/* Realloc signature buffer with new signature length */
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Sign sha256 hash\n");
	ret = pfunc->C_Sign(sess, msg_sha256, msg_sha256_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	tls_mac_params.prfHashMechanism = CKM_SHA384;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, master_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign sha384 hash\n");
	ret = pfunc->C_Sign(sess, msg_sha384, msg_sha384_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	tmp = signature_len;
	signature_len *= 2;
	signature = realloc(signature, signature_len);
	if (CHECK_EXPECTED(signature, "Allocation error"))
		goto end;

	TEST_OUT("Initialize sign operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, master_hsecretkey);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Sign message with signature buffer bigger that needed\n");
	ret = pfunc->C_Sign(sess, msg_sha256, msg_sha256_len, signature,
			    &signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Sign"))
		goto end;

	TEST_OUT("Check updated signature buffer length\n");
	if (CHECK_EXPECTED(signature_len == tmp,
			   "Signature length not updated"))
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

void tests_pkcs11_sign_verify(void *lib_hdl, CK_VOID_PTR pfunc)
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
	if (CHECK_CK_RV(CKR_OK, "C_Initialize")) {
		TEST_RESULT(status);
		goto end;
	}

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

	if (sign_verify_rsa_pkcs(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_rsa_pss(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_eddsa(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_key_usage(pfunc) == TEST_FAIL)
		goto end;

	if (sign_verify_rsa_pkcs_plaintext_key(pfunc) == TEST_FAIL)
		goto end;

	status = sign_verify_tls(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
