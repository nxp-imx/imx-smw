// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_keymgr.h>

#include "os_mutex.h"
#include "util.h"
#include "util_lib.h"
#include "util_session.h"

/* ref: RFC 8446 - 7.1 Key Schedule
 * Citation:
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
 *           HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *   Where HkdfLabel is specified as:
 *
 *     struct {
 *         uint16 length = Length;
 *         opaque label<7..255> = "tls13 " + Label;
 *         opaque context<0..255> = Context;
 *     } HkdfLabel;
 */
#define TLS13_HL_KEY_SIZE	    2
#define TLS13_HL_KEY_MAX_LENGTH	    65535
#define TLS13_HL_LABEL_SIZE	    1
#define TLS13_HL_LABEL_MAX_LENGTH   255
#define TLS13_HL_CONTEXT_SIZE	    1
#define TLS13_HL_CONTEXT_MAX_LENGTH 255
#define TLS13_HKDF_LABEL_MAX_SIZE                                              \
	(TLS13_HL_KEY_SIZE + TLS13_HL_LABEL_SIZE + TLS13_HL_LABEL_MAX_LENGTH + \
	 TLS13_HL_CONTEXT_SIZE + TLS13_HL_CONTEXT_MAX_LENGTH)

#define TLS13_HS_KEY_LABEL	"key"
#define TLS13_HS_IV_LABEL	"iv"
#define TLS13_HS_FINISHED_LABEL "finished"
#define TLS13_PREFIX		("tls13 ")
#define TLS13_PREFIX_LENGTH	(6)

static CK_BYTE peer_buffer[] = {
	0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7,
	0x02, 0x70, 0x39, 0x8c, 0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc,
	0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63, 0x56,
	0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c,
	0x13, 0xc5, 0x8d, 0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f,
	0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab
};

static CK_BYTE context[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

static const char label_s_hs_traffic[] = "s hs traffic";
static const char label_key[] = TLS13_HS_KEY_LABEL;
static const char label_iv[] = TLS13_HS_IV_LABEL;
static const char label_finished[] = TLS13_HS_FINISHED_LABEL;

/* messagetosign */
static CK_BYTE msg[] = { 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
			 0x74, 0x6f, 0x73, 0x69, 0x67, 0x6e };

static CK_ULONG msg_len = 13;

static CK_BYTE data[] =
	"message to encrypt using authenticated encryption (CCM, GCM, POLY1305)";

static CK_BYTE aad[] = "additional data used for authenticated encryption";

static CK_BYTE iv[] = { 0x01, 0x02, 0x03, 0x04,	 0x05, 0x06,
			0x07, 0x08, 0x09, 0x010, 0x0A, 0x0B };

static CK_GCM_PARAMS params_AES_GCM = { .pAAD = aad,
					.ulAADLen = sizeof(aad),
					.pIv = iv,
					.ulIvLen = sizeof(iv),
					.ulTagBits = BYTES_TO_BITS(16) };

static CK_SALSA20_CHACHA20_POLY1305_PARAMS params_CHACHA = {
	.pAAD = aad,
	.ulAADLen = sizeof(aad),
	.pNonce = iv,
	.ulNonceLen = sizeof(iv)
};

static CK_RV tls13_expand_label(CK_HKDF_PARAMS_PTR params, const char *label,
				size_t labellen, uint8_t *data, size_t datalen,
				size_t keylen)
{
	uint8_t *info = NULL;
	struct smw_tls13_expand_label_args exp_args = { 0 };

	exp_args.label = (unsigned char *)label;
	if (SET_OVERFLOW(labellen, exp_args.label_length))
		return CKR_ARGUMENTS_BAD;

	if (SET_OVERFLOW(keylen, exp_args.length))
		return CKR_ARGUMENTS_BAD;

	exp_args.context = data;
	if (SET_OVERFLOW(datalen, exp_args.context_length))
		return CKR_ARGUMENTS_BAD;

	params->ulInfoLen = SMW_TLS13_EXPANDED_LABEL_LENGTH(&exp_args);
	if (params->ulInfoLen > TLS13_HKDF_LABEL_MAX_SIZE)
		return CKR_ARGUMENTS_BAD;

	info = malloc(params->ulInfoLen);
	if (!info)
		return CKR_HOST_MEMORY;

	exp_args.expanded_label_length = params->ulInfoLen;
	exp_args.expanded_label = info;

	if (smw_tls13_expand_label(&exp_args) != SMW_STATUS_OK) {
		free(info);
		return CKR_ARGUMENTS_BAD;
	}

	params->pInfo = info;
	return CKR_OK;
}

static int object_derive_key_tls13_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
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

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_HKDF_PARAMS tls13_params = { 0 };
	CK_MECHANISM tls13_mech = { CKM_HKDF_DERIVE, (void *)&tls13_params,
				    sizeof(tls13_params) };

	CK_OBJECT_CLASS derive_key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	if (!util_lib_is_mech_supported(pfunc, 0, genmech.mechanism)) {
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
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Check invalid mechanism\n");

	tls13_mech.mechanism = CKM_ECDSA;
	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Null TLS13 mechanism parameter\n");
	tls13_mech.mechanism = CKM_HKDF_DERIVE;
	tls13_mech.pParameter = NULL;
	tls13_mech.ulParameterLen = 0;
	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid TLS13 mechanism parameter length\n");
	tls13_mech.pParameter = &tls13_params;
	tls13_mech.ulParameterLen = 1;
	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid extract/expand value\n");
	tls13_mech.pParameter = &tls13_params;
	tls13_mech.ulParameterLen = sizeof(tls13_params);
	tls13_params.bExpand = false;
	tls13_params.bExtract = false;
	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey"))
		goto end;

	TEST_OUT("Invalid Info parameter\n");
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	tls13_params.pInfo = NULL;
	tls13_params.ulInfoLen = 0;
	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_key);
	if (CHECK_CK_RV(CKR_ARGUMENTS_BAD, "C_DeriveKey"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_tls13(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL bsensitive = CK_FALSE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
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

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_HKDF_PARAMS tls13_params = { 0 };
	CK_MECHANISM tls13_mech = { CKM_HKDF_DERIVE, (void *)&tls13_params,
				    sizeof(tls13_params) };

	CK_OBJECT_CLASS derive_key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_encryption_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE derived_iv = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE s_hs_traffic_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_ULONG derived_key_len = 32;
	CK_KEY_TYPE derived_key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &derive_key_class, sizeof(derive_key_class) },
		{ CKA_KEY_TYPE, &derived_key_type, sizeof(derived_key_type) },
		{ CKA_VALUE_LEN, &derived_key_len, sizeof(derived_key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE keyAttrSensitive[] = {
		{ CKA_SENSITIVE, &bsensitive, sizeof(bsensitive) },
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	if (!util_lib_is_mech_supported(pfunc, 0, genmech.mechanism)) {
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
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	ret = tls13_expand_label(&tls13_params, label_s_hs_traffic,
				 strlen(label_s_hs_traffic), context,
				 ARRAY_SIZE(context), derived_key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Get sensitive attribute\n");
	ret = pfunc->C_GetAttributeValue(sess, s_hs_traffic_key,
					 keyAttrSensitive,
					 ARRAY_SIZE(keyAttrSensitive));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (CHECK_EXPECTED(bsensitive, "Got key sensitive %d expected %d",
			   bsensitive, CK_TRUE))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	derived_key_len = 16;
	derived_key_type = CKK_AES;
	derived_key_allowed_mech = CKM_AES_GCM;
	derived_key_template[4].type = CKA_ENCRYPT;
	ret = tls13_expand_label(&tls13_params, label_key, strlen(label_key),
				 NULL, 0, derived_key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, s_hs_traffic_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Get sensitive attribute\n");
	ret = pfunc->C_GetAttributeValue(sess, derived_encryption_key,
					 keyAttrSensitive,
					 ARRAY_SIZE(keyAttrSensitive));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (CHECK_EXPECTED(bsensitive, "Got key sensitive %d expected %d",
			   bsensitive, CK_TRUE))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	derived_key_len = 16;
	derived_key_type = CKK_GENERIC_SECRET;
	derived_key_allowed_mech = CKM_AES_GCM;
	derived_key_template[4].type = CKA_ENCRYPT;
	ret = tls13_expand_label(&tls13_params, label_iv, strlen(label_iv),
				 NULL, 0, derived_key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, s_hs_traffic_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template), &derived_iv);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Delete the IV\n");
	ret = pfunc->C_DestroyObject(sess, derived_iv);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the handshake key\n");
	ret = pfunc->C_DestroyObject(sess, derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the secret key\n");
	ret = pfunc->C_DestroyObject(sess, s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the ecdhe key\n");
	ret = pfunc->C_DestroyObject(sess, ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

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

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	if (tls13_params.pInfo)
		free(tls13_params.pInfo);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_tls13_encrypt_decrypt(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
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

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_HKDF_PARAMS tls13_params = { 0 };
	CK_MECHANISM tls13_mech = { CKM_HKDF_DERIVE, (void *)&tls13_params,
				    sizeof(tls13_params) };

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_encryption_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE s_hs_traffic_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_MECHANISM_TYPE encryption_key_allowed_mech = { CKM_AES_GCM };
	CK_ULONG key_len = 32;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_ATTRIBUTE encryption_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &encryption_key_allowed_mech,
		  sizeof(encryption_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	CK_MECHANISM encrypt_decrypt_mech = { CKM_AES_GCM, &params_AES_GCM,
					      sizeof(params_AES_GCM) };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;
	CK_ULONG data_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	if (!util_lib_is_mech_supported(pfunc, 0, genmech.mechanism)) {
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
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	ret = tls13_expand_label(&tls13_params, label_s_hs_traffic,
				 strlen(label_s_hs_traffic), context,
				 ARRAY_SIZE(context), key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	key_len = 16;
	key_type = CKK_AES;
	ret = tls13_expand_label(&tls13_params, label_key, strlen(label_key),
				 NULL, 0, key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, s_hs_traffic_key,
				 encryption_key_template,
				 ARRAY_SIZE(encryption_key_template),
				 &derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Initialize encrypt operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	/* Set a wrong encrypted data length */
	encrypted_data_len = 2;

	/* Encrypt message when encrypted data buffer too small */
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), NULL_PTR,
				     &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	encrypted_data_len += 16;
	encrypted_data =
		(CK_BYTE_PTR)calloc(encrypted_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	TEST_OUT("Encrypt message\n");
	data_len = sizeof(data);
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), encrypted_data,
				     &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	data_len = 16;
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[sizeof(data)],
				    &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Initialize decrypt operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     NULL_PTR, &recovered_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	recovered_data =
		(CK_BYTE_PTR)calloc(recovered_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	TEST_OUT("Decrypt encrypted data\n");
	data_len = recovered_data_len;
	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     recovered_data, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	ret = pfunc->C_DecryptFinal(sess, recovered_data + data_len, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
		goto end;

	TEST_DUMP_HEX("Recovered_data", recovered_data, recovered_data_len);

	if (!util_compare_buffers(data, sizeof(data), recovered_data,
				  recovered_data_len)) {
		TEST_OUT("Decrypted data and plaintext are not same\n");
		goto end;
	}

	TEST_OUT("Delete the handshake key\n");
	ret = pfunc->C_DestroyObject(sess, derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the secret key\n");
	ret = pfunc->C_DestroyObject(sess, s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the ecdhe key\n");
	ret = pfunc->C_DestroyObject(sess, ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

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
	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	if (tls13_params.pInfo)
		free(tls13_params.pInfo);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int
object_derive_key_tls13_encrypt_decrypt_all_aead(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
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

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_HKDF_PARAMS tls13_params = { 0 };
	CK_MECHANISM tls13_mech = { CKM_HKDF_DERIVE, (void *)&tls13_params,
				    sizeof(tls13_params) };

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_encryption_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE s_hs_traffic_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_MECHANISM_TYPE encryption_key_allowed_mech[] = {
		CKM_AES_GCM, CKM_CHACHA20_POLY1305
	};
	CK_ULONG key_len = 32;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_ATTRIBUTE encryption_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &encryption_key_allowed_mech,
		  sizeof(encryption_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	CK_MECHANISM encrypt_decrypt_chacha_mech = { CKM_CHACHA20_POLY1305,
						     &params_CHACHA,
						     sizeof(params_CHACHA) };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;
	CK_ULONG data_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	if (!util_lib_is_mech_supported(pfunc, 0, genmech.mechanism)) {
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
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	ret = tls13_expand_label(&tls13_params, label_s_hs_traffic,
				 strlen(label_s_hs_traffic), context,
				 ARRAY_SIZE(context), key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	key_len = 32;
	key_type = CKK_AES;
	ret = tls13_expand_label(&tls13_params, label_key, strlen(label_key),
				 NULL, 0, key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, s_hs_traffic_key,
				 encryption_key_template,
				 ARRAY_SIZE(encryption_key_template),
				 &derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Initialize encrypt operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_chacha_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	/* Set a wrong encrypted data length */
	encrypted_data_len = 2;

	/* Fetch the encrypted data buffer length */
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), NULL_PTR,
				     &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	encrypted_data_len += 16;
	encrypted_data =
		(CK_BYTE_PTR)calloc(encrypted_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	TEST_OUT("Encrypt message\n");
	data_len = sizeof(data);
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), encrypted_data,
				     &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	data_len = 16;
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[sizeof(data)],
				    &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Initialize decrypt operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_chacha_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     NULL_PTR, &recovered_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	recovered_data =
		(CK_BYTE_PTR)calloc(recovered_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	TEST_OUT("Decrypt encrypted data\n");
	data_len = recovered_data_len;
	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     recovered_data, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	ret = pfunc->C_DecryptFinal(sess, recovered_data + data_len, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
		goto end;

	TEST_DUMP_HEX("Recovered_data", recovered_data, recovered_data_len);

	if (!util_compare_buffers(data, sizeof(data), recovered_data,
				  recovered_data_len)) {
		TEST_OUT("Decrypted data and plaintext are not same\n");
		goto end;
	}

	TEST_OUT("Delete the handshake key\n");
	ret = pfunc->C_DestroyObject(sess, derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the secret key\n");
	ret = pfunc->C_DestroyObject(sess, s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the ecdhe key\n");
	ret = pfunc->C_DestroyObject(sess, ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

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
	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	if (tls13_params.pInfo)
		free(tls13_params.pInfo);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_tls13_sign_verify(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
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

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_HKDF_PARAMS tls13_params = { 0 };
	CK_MECHANISM tls13_mech = { CKM_HKDF_DERIVE, (void *)&tls13_params,
				    sizeof(tls13_params) };

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_finished_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE s_hs_traffic_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_MECHANISM_TYPE finished_key_allowed_mech = { CKM_SHA256_HMAC };
	CK_ULONG key_len = 32;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_ATTRIBUTE finished_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &finished_key_allowed_mech,
		  sizeof(finished_key_allowed_mech) },
		{ CKA_SIGN, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	CK_MECHANISM sign_verify_mech = { .mechanism = CKM_SHA256_HMAC };
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	if (!util_lib_is_mech_supported(pfunc, 0, genmech.mechanism)) {
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
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	ret = tls13_expand_label(&tls13_params, label_s_hs_traffic,
				 strlen(label_s_hs_traffic), context,
				 ARRAY_SIZE(context), key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	key_len = 32;
	key_type = CKK_SHA256_HMAC;
	ret = tls13_expand_label(&tls13_params, label_finished,
				 strlen(label_finished), NULL, 0, key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, s_hs_traffic_key,
				 finished_key_template,
				 ARRAY_SIZE(finished_key_template),
				 &derived_finished_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Initialize encrypt operation\n");
	ret = pfunc->C_SignInit(sess, &sign_verify_mech, derived_finished_key);
	if (CHECK_CK_RV(CKR_OK, "C_SignInit"))
		goto end;

	TEST_OUT("Get signature length (use NULL signature buffer)\n");
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

	TEST_OUT("Initialize verify operation\n");
	ret = pfunc->C_VerifyInit(sess, &sign_verify_mech,
				  derived_finished_key);
	if (CHECK_CK_RV(CKR_OK, "C_VerifyInit"))
		goto end;

	TEST_OUT("Verify signature\n");
	ret = pfunc->C_Verify(sess, msg, msg_len, signature, signature_len);
	if (CHECK_CK_RV(CKR_OK, "C_Verify"))
		goto end;

	TEST_OUT("Delete the handshake key\n");
	ret = pfunc->C_DestroyObject(sess, derived_finished_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the secret key\n");
	ret = pfunc->C_DestroyObject(sess, s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the ecdhe key\n");
	ret = pfunc->C_DestroyObject(sess, ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

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
	if (signature)
		free(signature);

	if (tls13_params.pInfo)
		free(tls13_params.pInfo);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int object_derive_key_tls13_edwards_enc_dec(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
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

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_HKDF_PARAMS tls13_params = { 0 };
	CK_MECHANISM tls13_mech = { CKM_HKDF_DERIVE, (void *)&tls13_params,
				    sizeof(tls13_params) };

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_encryption_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE s_hs_traffic_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_MECHANISM_TYPE encryption_key_allowed_mech = { CKM_AES_GCM };
	CK_ULONG key_len = 32;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_ATTRIBUTE encryption_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &encryption_key_allowed_mech,
		  sizeof(encryption_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	CK_MECHANISM encrypt_decrypt_mech = { CKM_AES_GCM, &params_AES_GCM,
					      sizeof(params_AES_GCM) };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;
	CK_ULONG data_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	if (!util_lib_is_mech_supported(pfunc, 0, genmech.mechanism)) {
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
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	ret = tls13_expand_label(&tls13_params, label_s_hs_traffic,
				 strlen(label_s_hs_traffic), context,
				 ARRAY_SIZE(context), key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	key_len = 16;
	key_type = CKK_AES;
	ret = tls13_expand_label(&tls13_params, label_key, strlen(label_key),
				 NULL, 0, key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, s_hs_traffic_key,
				 encryption_key_template,
				 ARRAY_SIZE(encryption_key_template),
				 &derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Initialize encrypt operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	/* Set a wrong encrypted data length */
	encrypted_data_len = 2;

	/* Encrypt message when encrypted data buffer too small */
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), NULL_PTR,
				     &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	encrypted_data_len += 16;
	encrypted_data =
		(CK_BYTE_PTR)calloc(encrypted_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	TEST_OUT("Encrypt message\n");
	data_len = sizeof(data);
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), encrypted_data,
				     &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	data_len = 16;
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[sizeof(data)],
				    &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Initialize decrypt operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     NULL_PTR, &recovered_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	recovered_data =
		(CK_BYTE_PTR)calloc(recovered_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	TEST_OUT("Decrypt encrypted data\n");
	data_len = recovered_data_len;
	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     recovered_data, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	ret = pfunc->C_DecryptFinal(sess, recovered_data + data_len, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
		goto end;

	TEST_DUMP_HEX("Recovered_data", recovered_data, recovered_data_len);

	if (!util_compare_buffers(data, sizeof(data), recovered_data,
				  recovered_data_len)) {
		TEST_OUT("Decrypted data and plaintext are not same\n");
		goto end;
	}

	TEST_OUT("Delete the handshake key\n");
	ret = pfunc->C_DestroyObject(sess, derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the secret key\n");
	ret = pfunc->C_DestroyObject(sess, s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the ecdhe key\n");
	ret = pfunc->C_DestroyObject(sess, ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

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
	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	if (tls13_params.pInfo)
		free(tls13_params.pInfo);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int
object_derive_key_tls13_montgomery_enc_dec(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_BBOOL ck_true = CK_TRUE;

	CK_OBJECT_HANDLE hpubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hprivkey = CK_INVALID_HANDLE;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_MONTGOMERY_KEY_PAIR_GEN };
	CK_MECHANISM_TYPE base_key_allowed_mech = { CKM_HKDF_DERIVE };
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

	CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
	CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, (void *)&ecdh_params,
				   sizeof(ecdh_params) };
	CK_HKDF_PARAMS tls13_params = { 0 };
	CK_MECHANISM tls13_mech = { CKM_HKDF_DERIVE, (void *)&tls13_params,
				    sizeof(tls13_params) };

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE derived_encryption_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE s_hs_traffic_key = CK_INVALID_HANDLE;
	CK_MECHANISM_TYPE derived_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_MECHANISM_TYPE encryption_key_allowed_mech = { CKM_AES_GCM };
	CK_ULONG key_len = 32;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &derived_key_allowed_mech,
		  sizeof(derived_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_ATTRIBUTE encryption_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &encryption_key_allowed_mech,
		  sizeof(encryption_key_allowed_mech) },
		{ CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL) }
	};
	CK_MECHANISM_TYPE ecdhe_key_allowed_mech = { CKM_HKDF_DERIVE };
	CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE ecdhe_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_ALLOWED_MECHANISMS, &ecdhe_key_allowed_mech,
		  sizeof(ecdhe_key_allowed_mech) },
		{ CKA_DERIVE, &ck_true, sizeof(CK_BBOOL) },
	};

	CK_MECHANISM encrypt_decrypt_mech = { CKM_AES_GCM, &params_AES_GCM,
					      sizeof(params_AES_GCM) };

	CK_BYTE_PTR encrypted_data = NULL_PTR;
	CK_ULONG encrypted_data_len = 0;
	CK_BYTE_PTR recovered_data = NULL_PTR;
	CK_ULONG recovered_data_len = 0;
	CK_ULONG data_len = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (!util_lib_is_mech_supported(pfunc, 0, base_key_allowed_mech)) {
		status = TEST_SKIP;
		goto end;
	}

	if (!util_lib_is_mech_supported(pfunc, 0, genmech.mechanism)) {
		status = TEST_SKIP;
		goto end;
	}

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (CHECK_EXPECTED(util_to_asn1_string(&pubkey_attrs[0],
					       &x_curves[EC_X25519]),
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
	ecdh_params.ulPublicDataLen = sizeof(peer_buffer);

	ret = pfunc->C_DeriveKey(sess, &ecdh_mech, hprivkey, ecdhe_key_template,
				 ARRAY_SIZE(ecdhe_key_template), &ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	ret = tls13_expand_label(&tls13_params, label_s_hs_traffic,
				 strlen(label_s_hs_traffic), context,
				 ARRAY_SIZE(context), key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, ecdhe_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 &s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	free(tls13_params.pInfo);
	tls13_params.pInfo = NULL;

	TEST_OUT("Set CKM_HKDF_DERIVE mechanism parameters\n");
	tls13_params.prfHashMechanism = CKM_SHA256;
	tls13_params.bExpand = true;
	tls13_params.bExtract = false;
	key_len = 16;
	key_type = CKK_AES;
	ret = tls13_expand_label(&tls13_params, label_key, strlen(label_key),
				 NULL, 0, key_len);
	if (ret != CKR_OK)
		goto end;

	ret = pfunc->C_DeriveKey(sess, &tls13_mech, s_hs_traffic_key,
				 encryption_key_template,
				 ARRAY_SIZE(encryption_key_template),
				 &derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DeriveKey"))
		goto end;

	TEST_OUT("Initialize encrypt operation\n");
	ret = pfunc->C_EncryptInit(sess, &encrypt_decrypt_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptInit"))
		goto end;

	/* Set a wrong encrypted data length */
	encrypted_data_len = 2;

	/* Encrypt message when encrypted data buffer too small */
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), NULL_PTR,
				     &encrypted_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	encrypted_data_len += 16;
	encrypted_data =
		(CK_BYTE_PTR)calloc(encrypted_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(encrypted_data, "Allocation error"))
		goto end;

	TEST_OUT("Encrypt message\n");
	data_len = sizeof(data);
	ret = pfunc->C_EncryptUpdate(sess, data, sizeof(data), encrypted_data,
				     &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptUpdate"))
		goto end;

	data_len = 16;
	ret = pfunc->C_EncryptFinal(sess, &encrypted_data[sizeof(data)],
				    &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_EncryptFinal"))
		goto end;

	TEST_OUT("Initialize decrypt operation\n");
	ret = pfunc->C_DecryptInit(sess, &encrypt_decrypt_mech,
				   derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptInit"))
		goto end;

	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     NULL_PTR, &recovered_data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	recovered_data =
		(CK_BYTE_PTR)calloc(recovered_data_len, sizeof(CK_BYTE));
	if (CHECK_EXPECTED(recovered_data, "Allocation error"))
		goto end;

	TEST_OUT("Decrypt encrypted data\n");
	data_len = recovered_data_len;
	ret = pfunc->C_DecryptUpdate(sess, encrypted_data, encrypted_data_len,
				     recovered_data, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptUpdate"))
		goto end;

	ret = pfunc->C_DecryptFinal(sess, recovered_data + data_len, &data_len);
	if (CHECK_CK_RV(CKR_OK, "C_DecryptFinal"))
		goto end;

	TEST_DUMP_HEX("Recovered_data", recovered_data, recovered_data_len);

	if (!util_compare_buffers(data, sizeof(data), recovered_data,
				  recovered_data_len)) {
		TEST_OUT("Decrypted data and plaintext are not same\n");
		goto end;
	}

	TEST_OUT("Delete the handshake key\n");
	ret = pfunc->C_DestroyObject(sess, derived_encryption_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the secret key\n");
	ret = pfunc->C_DestroyObject(sess, s_hs_traffic_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	TEST_OUT("Delete the ecdhe key\n");
	ret = pfunc->C_DestroyObject(sess, ecdhe_key);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

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
	if (encrypted_data)
		free(encrypted_data);

	if (recovered_data)
		free(recovered_data);

	if (tls13_params.pInfo)
		free(tls13_params.pInfo);

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_derive_key_tls1_3(void *lib_hdl, CK_VOID_PTR pfunc)
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
		SETUP_FAIL();
		goto end;
	}

	if (object_derive_key_tls13_bad_param(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_tls13(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_tls13_encrypt_decrypt(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_tls13_encrypt_decrypt_all_aead(pfunc) ==
	    TEST_FAIL)
		goto end;

	if (object_derive_key_tls13_sign_verify(pfunc) == TEST_FAIL)
		goto end;

	if (object_derive_key_tls13_edwards_enc_dec(pfunc) == TEST_FAIL)
		goto end;

	status = object_derive_key_tls13_montgomery_enc_dec(pfunc);

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
