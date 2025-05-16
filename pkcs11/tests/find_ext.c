// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include <string.h>
#include <smw/object.h>

#include "local.h"
#include "os_mutex.h"
#include "util.h"
#include "util_lib.h"
#include "util_session.h"

#define SMW_SIGN_ECDSA(_curve, _hash)                                          \
	SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_##_curve,      \
						 SMW_ATTR_HASH_##_hash)

#define SMW_SIGN_EDDSA(_curve, _hash, _param)                                  \
	SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA(                              \
		SMW_ATTR_CURVE_##_curve, SMW_ATTR_HASH_##_hash,                \
		SMW_ATTR_SIGN_PARAM_EDDSA_##_param)

#define SMW_SIGN_RSA(_scheme, _hash)                                           \
	SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(SMW_ATTR_MODE_##_scheme,        \
					       SMW_ATTR_HASH_##_hash, 0)

#define SMW_SIGN_HMAC(_hash) SMW_ATTR_ALGO_MAC_HMAC(SMW_ATTR_HASH_##_hash, 0)

#define SMW_ENCRYPT(_algo, _mode)                                              \
	SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(SMW_ATTR_ALGO_##_algo,              \
					   SMW_ATTR_MODE_##_mode)

#define SMW_USAGE_FLAGS(_sign, _verify, _encrypt, _decrypt)                    \
	((_verify ? SMW_ATTR_USAGE_VERIFY_MESSAGE : 0) |                       \
	 (_sign ? SMW_ATTR_USAGE_SIGN_MESSAGE : 0) |                           \
	 (_encrypt ? SMW_ATTR_USAGE_ENCRYPT : 0) |                             \
	 (_decrypt ? SMW_ATTR_USAGE_DECRYPT : 0))

#define EC_KEYPAIR(_type, _size, _perm_algo, _allowed_mech, _curve, _verify,   \
		   _sign)                                                      \
	{                                                                      \
		.is_public = true, .is_private = true, .ec_curve = _curve,     \
		.key_desc.type_name = SMW_KEY_TYPE_NAME_##_type,               \
		.key_desc.security_size = _size,                               \
		.key_desc.attributes.attributes =                              \
			SMW_ATTR_PERSISTENCE_PERSISTENT,                       \
		.key_desc.attributes.permitted_algo = _perm_algo,              \
		.p11_key.key_type = CKK_EC,                                    \
		.p11_key.allowed_mech = _allowed_mech,                         \
		.p11_key.verify = _verify, .p11_key.sign = _sign,              \
	}

#define ED_KEYPAIR(_type, _size, _perm_algo, _allowed_mech, _curve, _verify,   \
		   _sign)                                                      \
	{                                                                      \
		.is_public = true, .is_private = true, .ec_curve = _curve,     \
		.key_desc.type_name = SMW_KEY_TYPE_NAME_##_type,               \
		.key_desc.security_size = _size,                               \
		.key_desc.attributes.attributes =                              \
			SMW_ATTR_PERSISTENCE_PERSISTENT,                       \
		.key_desc.attributes.permitted_algo = _perm_algo,              \
		.p11_key.key_type = CKK_EC_EDWARDS,                            \
		.p11_key.allowed_mech = _allowed_mech,                         \
		.p11_key.verify = _verify, .p11_key.sign = _sign,              \
	}

#define RSA_KEYPAIR(_size, _perm_algo, _allowed_mech, _verify, _sign)          \
	{                                                                      \
		.is_public = true, .is_private = true,                         \
		.key_desc.type_name = SMW_KEY_TYPE_NAME_RSA,                   \
		.key_desc.security_size = _size,                               \
		.key_desc.attributes.attributes =                              \
			SMW_ATTR_PERSISTENCE_PERSISTENT,                       \
		.key_desc.attributes.permitted_algo = _perm_algo,              \
		.p11_key.key_type = CKK_RSA,                                   \
		.p11_key.allowed_mech = _allowed_mech,                         \
		.p11_key.verify = _verify, .p11_key.sign = _sign,              \
	}

#define AES_KEY(_size, _perm_algo, _allowed_mech, _encrypt, _decrypt)          \
	{                                                                      \
		.is_secret = true,                                             \
		.key_desc.type_name = SMW_KEY_TYPE_NAME_AES,                   \
		.key_desc.security_size = _size,                               \
		.key_desc.attributes.attributes =                              \
			SMW_ATTR_PERSISTENCE_PERSISTENT,                       \
		.key_desc.attributes.permitted_algo = _perm_algo,              \
		.p11_key.key_type = CKK_AES,                                   \
		.p11_key.allowed_mech = _allowed_mech,                         \
		.p11_key.encrypt = _encrypt, .p11_key.decrypt = _decrypt,      \
	}

#define HMAC_KEY(_size, _hash, _perm_algo, _allowed_mech, _sign, _verify)      \
	{                                                                      \
		.is_secret = true,                                             \
		.key_desc.type_name = SMW_KEY_TYPE_NAME_HMAC,                  \
		.key_desc.security_size = _size,                               \
		.key_desc.attributes.attributes =                              \
			SMW_ATTR_PERSISTENCE_PERSISTENT,                       \
		.key_desc.attributes.permitted_algo = _perm_algo,              \
		.p11_key.key_type = CKK_##_hash##_HMAC,                        \
		.p11_key.allowed_mech = _allowed_mech, .p11_key.sign = _sign,  \
		.p11_key.verify = _verify,                                     \
	}

struct p11_key {
	CK_KEY_TYPE key_type;
	CK_BBOOL encrypt;
	CK_BBOOL decrypt;
	CK_BBOOL verify;
	CK_BBOOL sign;
	CK_MECHANISM_TYPE allowed_mech;
};

static struct smw_object {
	unsigned int obj_id;
	bool is_public;
	bool is_private;
	bool is_secret;
	unsigned int ec_curve;
	struct smw_key_descriptor key_desc;
	struct p11_key p11_key;
} objects_key[] = {
	EC_KEYPAIR(SECP_R1, 256, SMW_SIGN_ECDSA(SECP_R1, SHA256),
		   CKM_ECDSA_SHA256, SECP_R1_256, CK_TRUE, CK_FALSE),
	ED_KEYPAIR(ED25519, 255, SMW_SIGN_EDDSA(ED25519, NONE, NONE), CKM_EDDSA,
		   EC_ED25519, CK_TRUE, CK_TRUE),
	RSA_KEYPAIR(2048, SMW_SIGN_RSA(PKCS1_1_5, SHA512), CKM_SHA512_RSA_PKCS,
		    CK_TRUE, CK_FALSE),
	AES_KEY(256, SMW_ENCRYPT(AES, ECB_NO_PAD), CKM_AES_ECB, CK_TRUE,
		CK_FALSE),

#if !SECO_TESTS_ENABLED
	HMAC_KEY(256, SHA256, SMW_SIGN_HMAC(SHA256), CKM_SHA256_HMAC, CK_TRUE,
		 CK_TRUE)
#endif
};

static int export_ec_public_key(struct smw_object *obj, CK_BYTE_PTR ec_point,
				CK_ULONG ec_point_len)
{
	int status = TEST_FAIL;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_export_key_args args = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	uint8_t *public_data = NULL;
	uint8_t *check_pub_data = NULL;
	size_t public_len = 0;
	size_t check_pub_len = 0;

	args.key_descriptor = &obj->key_desc;
	obj->key_desc.buffer = &key_buffer;

	smw_status = smw_get_key_buffers_lengths(&obj->key_desc);
	if (CHECK_EXPECTED(smw_status == SMW_STATUS_OK,
			   "smw_get_key_buffers_lengths ret %d", smw_status))
		goto end;

	/* Allocate the public key buffer */
	if (CHECK_EXPECTED(key_buffer.gen.public_length,
			   "Public key length invalid"))
		goto end;

	key_buffer.gen.public_data = calloc(1, key_buffer.gen.public_length);
	if (CHECK_EXPECTED(key_buffer.gen.public_data, "Out of memory"))
		goto end;

	smw_status = smw_export_key(&args);
	if (CHECK_EXPECTED(smw_status == SMW_STATUS_OK, "smw_export_key ret %d",
			   smw_status))
		goto end;

	if (obj->p11_key.key_type == CKK_EC) {
		if (!util_asn1_get_field_octet_string(ec_point, ec_point_len,
						      &public_data,
						      &public_len))
			goto end;

		/* Check if ec_point start with Uncompress key tag */
		if (CHECK_EXPECTED(public_data[0] == ANSI_UNCOMPRESS_KEY_TAG,
				   "EC Public point start with 0x%02x",
				   public_data[0]))
			goto end;
		check_pub_data = &public_data[1];
		check_pub_len = public_len - 1;

	} else {
		check_pub_data = ec_point;
		check_pub_len = ec_point_len;
	}

	/* Verify Public buffer */
	if (!CHECK_EXPECTED(util_compare_buffers(check_pub_data, check_pub_len,
						 key_buffer.gen.public_data,
						 key_buffer.gen.public_length),
			    "Invalid EC Public key"))
		status = TEST_PASS;

end:
	if (key_buffer.gen.public_data)
		free(key_buffer.gen.public_data);

	obj->key_desc.buffer = NULL;

	return status;
}

static int export_rsa_public_key(struct smw_object *obj, CK_BYTE_PTR pub_exp,
				 CK_ULONG pub_exp_len, CK_BYTE_PTR modulus,
				 CK_ULONG modulus_len)
{
	int status = TEST_FAIL;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_export_key_args args = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };

	args.key_descriptor = &obj->key_desc;
	obj->key_desc.buffer = &key_buffer;

	smw_status = smw_get_key_buffers_lengths(&obj->key_desc);
	if (CHECK_EXPECTED(smw_status == SMW_STATUS_OK,
			   "smw_get_key_buffers_lengths ret %d", smw_status))
		goto end;

	/* Allocate the public exponent buffer */
	if (CHECK_EXPECTED(key_buffer.rsa.public_length,
			   "Public exponent length invalid"))
		goto end;

	key_buffer.rsa.public_data = calloc(1, key_buffer.rsa.public_length);
	if (CHECK_EXPECTED(key_buffer.rsa.public_data, "Out of memory"))
		goto end;

	/* Allocate the Modulus buffer */
	if (CHECK_EXPECTED(key_buffer.rsa.modulus_length,
			   "Modulus length invalid"))
		goto end;

	key_buffer.rsa.modulus = calloc(1, key_buffer.rsa.modulus_length);
	if (CHECK_EXPECTED(key_buffer.rsa.modulus, "Out of memory"))
		goto end;

	smw_status = smw_export_key(&args);
	if (CHECK_EXPECTED(smw_status == SMW_STATUS_OK, "smw_export_key ret %d",
			   smw_status))
		goto end;

	/* Verify Public buffer */
	if (!CHECK_EXPECTED(util_compare_buffers(pub_exp, pub_exp_len,
						 key_buffer.rsa.public_data,
						 key_buffer.rsa.public_length),
			    "Invalid RSA Public Exponent"))
		status = TEST_PASS;

	/* Verify Modulus buffer */
	if (!CHECK_EXPECTED(util_compare_buffers(modulus, modulus_len,
						 key_buffer.rsa.modulus,
						 key_buffer.rsa.modulus_length),
			    "Invalid RSA Modulus"))
		status = TEST_PASS;

end:
	if (key_buffer.rsa.public_data)
		free(key_buffer.rsa.public_data);

	if (key_buffer.rsa.modulus)
		free(key_buffer.rsa.modulus);

	obj->key_desc.buffer = NULL;

	return status;
}

static int generate_objects_key(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_generate_key_args genkey_args = { 0 };
	struct smw_object *obj = objects_key;
	size_t i = 0;

	SUBTEST_START();

	for (; i < ARRAY_SIZE(objects_key); i++, obj++) {
		if (!util_lib_is_mech_supported(pfunc, 0,
						obj->p11_key.allowed_mech)) {
			status = TEST_SKIP;
			goto end;
		}

		obj->key_desc.attributes.usage_flags =
			SMW_USAGE_FLAGS(obj->p11_key.sign, obj->p11_key.verify,
					obj->p11_key.encrypt,
					obj->p11_key.decrypt);
		genkey_args.key_descriptor = &obj->key_desc;

		/* Generate a key pair with SMW API */
		smw_status = smw_generate_key(&genkey_args);
		if (smw_status != SMW_STATUS_OK &&
		    smw_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
			TEST_OUT("Generate key pair failed\n");
			goto end;
		}

		obj->obj_id = obj->key_desc.id;
	}

	status = TEST_PASS;

end:
	SUBTEST_END(status);
	return status;
}

static void delete_objects_key(void)
{
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_delete_key_args del_args = { 0 };

	size_t i = 0;

	for (; i < ARRAY_SIZE(objects_key); i++) {
		del_args.key_descriptor = &objects_key[i].key_desc;

		smw_status = smw_delete_key(&del_args);
		if (smw_status != SMW_STATUS_OK) {
			TEST_OUT("smw_delete_key of key 0x%08x ret %d\n",
				 objects_key[i].obj_id, smw_status);
		}
	}
}

static int check_ec_public_key(CK_FUNCTION_LIST_PTR pfunc,
			       CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE hpubkey,
			       struct smw_object *obj)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_BYTE_PTR ec_params = NULL;
	CK_ULONG ec_params_len = 0;
	CK_BYTE_PTR ec_point = NULL;
	CK_ULONG ec_point_len = 0;
	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_EC_POINT, NULL, 0 },
	};
	const struct asn1_ec_curve *ec_curve = NULL;

	ret = pfunc->C_GetAttributeValue(sess, hpubkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "Get length of EC Public Key Attributes"))
		goto end;

	ec_params_len = key_attrs[0].ulValueLen;
	if (ec_params_len) {
		ec_params = calloc(1, ec_params_len);
		if (CHECK_EXPECTED(ec_params, "Out of memory"))
			goto end;

		key_attrs[0].pValue = ec_params;
	} else {
		goto end;
	}

	ec_point_len = key_attrs[1].ulValueLen;
	if (ec_point_len) {
		ec_point = calloc(1, ec_point_len);
		if (CHECK_EXPECTED(ec_point, "Out of memory"))
			goto end;

		key_attrs[1].pValue = ec_point;
	}

	ret = pfunc->C_GetAttributeValue(sess, hpubkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "Get EC Public Key Attributes"))
		goto end;

	/* Verify all expected attributes */
	switch (obj->p11_key.key_type) {
	case CKK_EC:
		ec_curve = &ec_curves[obj->ec_curve];
		break;

	case CKK_EC_EDWARDS:
		ec_curve = &ed_curves[obj->ec_curve];
		break;

	default:
		goto end;
	}

	if (CHECK_EXPECTED(util_compare_buffers(&ec_params[2],
						ec_params_len - 2,
						(unsigned char *)ec_curve->oid,
						ec_curve->oid_len),
			   "OID not identical"))
		goto end;

	status = export_ec_public_key(obj, ec_point, ec_point_len);

end:
	if (ec_params)
		free(ec_params);

	if (ec_point)
		free(ec_point);

	return status;
}

static int check_rsa_public_key(CK_FUNCTION_LIST_PTR pfunc,
				CK_SESSION_HANDLE sess,
				CK_OBJECT_HANDLE hpubkey,
				struct smw_object *obj)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_BYTE_PTR modulus = NULL;
	CK_ULONG modulus_len = 0;
	CK_BYTE_PTR pub_exp = NULL;
	CK_ULONG pub_exp_len = 0;
	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 },
	};

	ret = pfunc->C_GetAttributeValue(sess, hpubkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "Get length of RSA Public Key Attributes"))
		goto end;

	modulus_len = key_attrs[0].ulValueLen;
	if (modulus_len) {
		modulus = calloc(1, modulus_len);
		if (CHECK_EXPECTED(modulus, "Out of memory"))
			goto end;

		key_attrs[0].pValue = modulus;
	}

	pub_exp_len = key_attrs[1].ulValueLen;
	if (pub_exp_len) {
		pub_exp = calloc(1, pub_exp_len);
		if (CHECK_EXPECTED(pub_exp, "Out of memory"))
			goto end;

		key_attrs[1].pValue = pub_exp;
	}

	ret = pfunc->C_GetAttributeValue(sess, hpubkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "Get RSA Public Key Attributes"))
		goto end;

	status = export_rsa_public_key(obj, pub_exp, pub_exp_len, modulus,
				       modulus_len);

end:
	if (modulus)
		free(modulus);

	if (pub_exp)
		free(pub_exp);

	return status;
}

static int check_common_public_key(CK_FUNCTION_LIST_PTR pfunc,
				   CK_SESSION_HANDLE sess,
				   CK_OBJECT_HANDLE hpubkey,
				   struct smw_object *obj)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_KEY_TYPE key_type = CK_UNAVAILABLE_INFORMATION;
	CK_BBOOL encrypt = CK_FALSE;
	CK_BBOOL verify = CK_FALSE;
	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_ENCRYPT, &encrypt, sizeof(encrypt) },
		{ CKA_VERIFY, &verify, sizeof(verify) },
	};

	ret = pfunc->C_GetAttributeValue(sess, hpubkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "Get common Public Key Attributes"))
		goto end;

	/* Verify all expected attributes */
	status = TEST_PASS;

	if (CHECK_EXPECTED(key_type == obj->p11_key.key_type,
			   "Expected key type 0x%08lx got 0x%08lx",
			   obj->p11_key.key_type, key_type))
		status = TEST_FAIL;

	if (is_seco_subsystem())
		goto end;

	if (CHECK_EXPECTED(encrypt == obj->p11_key.encrypt,
			   "Expected Usage Encrypt %d got %d",
			   obj->p11_key.encrypt, encrypt))
		status = TEST_FAIL;

	if (CHECK_EXPECTED(verify == obj->p11_key.verify,
			   "Expected Usage Verify %d got %d",
			   obj->p11_key.verify, verify))
		status = TEST_FAIL;

end:
	return status;
}

static int check_common_private_key(CK_FUNCTION_LIST_PTR pfunc,
				    CK_SESSION_HANDLE sess,
				    CK_OBJECT_HANDLE hprivkey,
				    struct smw_object *obj)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_KEY_TYPE key_type = CK_UNAVAILABLE_INFORMATION;
	CK_BBOOL decrypt = CK_FALSE;
	CK_BBOOL sign = CK_FALSE;
	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_DECRYPT, &decrypt, sizeof(decrypt) },
		{ CKA_SIGN, &sign, sizeof(sign) },
	};

	ret = pfunc->C_GetAttributeValue(sess, hprivkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "Get common Private Key Attributes"))
		goto end;

	/* Verify all expected attributes */
	status = TEST_PASS;

	if (CHECK_EXPECTED(key_type == obj->p11_key.key_type,
			   "Expected key type 0x%08lx got 0x%08lx",
			   obj->p11_key.key_type, key_type))
		status = TEST_FAIL;

	if (is_seco_subsystem())
		goto end;

	if (CHECK_EXPECTED(decrypt == obj->p11_key.decrypt,
			   "Expected Usage Decrypt %d got %d",
			   obj->p11_key.decrypt, decrypt))
		status = TEST_FAIL;

	if (CHECK_EXPECTED(sign == obj->p11_key.sign,
			   "Expected Usage Sign %d got %d", obj->p11_key.sign,
			   sign))
		status = TEST_FAIL;

end:
	return status;
}

static int check_common_secret_key(CK_FUNCTION_LIST_PTR pfunc,
				   CK_SESSION_HANDLE sess,
				   CK_OBJECT_HANDLE hseckey,
				   struct smw_object *obj)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_KEY_TYPE key_type = CK_UNAVAILABLE_INFORMATION;
	CK_BBOOL decrypt = CK_FALSE;
	CK_BBOOL encrypt = CK_FALSE;
	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_ENCRYPT, &encrypt, sizeof(encrypt) },
		{ CKA_DECRYPT, &decrypt, sizeof(decrypt) },
	};

	ret = pfunc->C_GetAttributeValue(sess, hseckey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "Get common Secret Key Attributes"))
		goto end;

	/* Verify all expected attributes */
	status = TEST_PASS;

	if (CHECK_EXPECTED(key_type == obj->p11_key.key_type,
			   "Expected key type 0x%08lx got 0x%08lx",
			   obj->p11_key.key_type, key_type))
		status = TEST_FAIL;

	if (is_seco_subsystem())
		goto end;

	if (CHECK_EXPECTED(decrypt == obj->p11_key.decrypt,
			   "Expected Usage Decrypt %d got %d",
			   obj->p11_key.decrypt, decrypt))
		status = TEST_FAIL;

	if (CHECK_EXPECTED(encrypt == obj->p11_key.encrypt,
			   "Expected Usage Encrypt %d got %d",
			   obj->p11_key.encrypt, encrypt))
		status = TEST_FAIL;

end:
	return status;
}

static int check_public_keys(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE sess,
			     CK_OBJECT_HANDLE hpubkey)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL;
	unsigned int key_id = 0;
	size_t idx = 0;

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
	};

	ret = util_set_unique_id(unique_id, &unique_id_len, key_class, 0);
	if (ret != CKR_BUFFER_TOO_SMALL) {
		TEST_OUT("Get unique id len failed\n");
		goto end;
	}

	unique_id = calloc(1, unique_id_len);
	if (CHECK_EXPECTED(unique_id, "Out of memory"))
		goto end;

	TEST_OUT("Get Public key attribute\n");
	key_attrs[0].pValue = unique_id;
	key_attrs[0].ulValueLen = unique_id_len;

	ret = pfunc->C_GetAttributeValue(sess, hpubkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	ret = util_get_object_id(unique_id, unique_id_len, &key_id);
	if (ret != CKR_OK) {
		TEST_OUT("Get key id from unique id\n");
		goto end;
	}

	for (; idx < ARRAY_SIZE(objects_key); idx++) {
		if (key_id != objects_key[idx].obj_id)
			continue;

		status = check_common_public_key(pfunc, sess, hpubkey,
						 &objects_key[idx]);
		if (status == TEST_FAIL)
			break;

		switch (objects_key[idx].p11_key.key_type) {
		case CKK_EC:
		case CKK_EC_EDWARDS:
			status = check_ec_public_key(pfunc, sess, hpubkey,
						     &objects_key[idx]);
			break;

		case CKK_RSA:
			status = check_rsa_public_key(pfunc, sess, hpubkey,
						      &objects_key[idx]);
			break;

		default:
			break;
		}

		break;
	}

	TEST_OUT("%secognized Public key 0x%08x\n",
		 (status == TEST_PASS) ? "R" : "Unr", key_id);
end:
	if (unique_id)
		free(unique_id);

	return status;
}

static int check_private_keys(CK_FUNCTION_LIST_PTR pfunc,
			      CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE hprivkey)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL;
	unsigned int key_id = 0;
	size_t idx = 0;

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
	};

	ret = util_set_unique_id(unique_id, &unique_id_len, key_class, 0);
	if (ret != CKR_BUFFER_TOO_SMALL) {
		TEST_OUT("Get unique id len failed\n");
		goto end;
	}

	unique_id = calloc(1, unique_id_len);
	if (CHECK_EXPECTED(unique_id, "Out of memory"))
		goto end;

	TEST_OUT("Get Private key attribute\n");
	key_attrs[0].pValue = unique_id;
	key_attrs[0].ulValueLen = unique_id_len;

	ret = pfunc->C_GetAttributeValue(sess, hprivkey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	ret = util_get_object_id(unique_id, unique_id_len, &key_id);
	if (ret != CKR_OK) {
		TEST_OUT("Get key id from unique id\n");
		goto end;
	}

	for (; idx < ARRAY_SIZE(objects_key); idx++) {
		if (key_id != objects_key[idx].obj_id)
			continue;

		status = check_common_private_key(pfunc, sess, hprivkey,
						  &objects_key[idx]);
		if (status == TEST_FAIL || !objects_key[idx].is_public)
			break;

		/* If it's a keypair, verify also the public key values */
		switch (objects_key[idx].p11_key.key_type) {
		case CKK_EC:
		case CKK_EC_EDWARDS:
			status = check_ec_public_key(pfunc, sess, hprivkey,
						     &objects_key[idx]);
			break;

		case CKK_RSA:
			status = check_rsa_public_key(pfunc, sess, hprivkey,
						      &objects_key[idx]);
			break;

		default:
			break;
		}

		break;
	}

	TEST_OUT("%secognized Private key 0x%08x\n",
		 (status == TEST_PASS) ? "R" : "Unr", key_id);

end:
	if (unique_id)
		free(unique_id);

	return status;
}

static int check_secret_keys(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE sess,
			     CK_OBJECT_HANDLE hseckey)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_ULONG unique_id_len = 0;
	CK_UTF8CHAR_PTR unique_id = NULL;
	unsigned int key_id = 0;
	size_t idx = 0;

	CK_ATTRIBUTE key_attrs[] = {
		{ CKA_UNIQUE_ID, unique_id, unique_id_len },
	};

	ret = util_set_unique_id(unique_id, &unique_id_len, key_class, 0);
	if (ret != CKR_BUFFER_TOO_SMALL) {
		TEST_OUT("Get unique id len failed\n");
		goto end;
	}

	unique_id = calloc(1, unique_id_len);
	if (CHECK_EXPECTED(unique_id, "Out of memory"))
		goto end;

	TEST_OUT("Get Secret key attribute\n");
	key_attrs[0].pValue = unique_id;
	key_attrs[0].ulValueLen = unique_id_len;

	ret = pfunc->C_GetAttributeValue(sess, hseckey, key_attrs,
					 ARRAY_SIZE(key_attrs));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	ret = util_get_object_id(unique_id, unique_id_len, &key_id);
	if (ret != CKR_OK) {
		TEST_OUT("Get key id from unique id\n");
		goto end;
	}

	for (; idx < ARRAY_SIZE(objects_key); idx++) {
		if (key_id != objects_key[idx].obj_id)
			continue;

		status = check_common_secret_key(pfunc, sess, hseckey,
						 &objects_key[idx]);
		break;
	}

	TEST_OUT("%secognized Secret key 0x%08x\n",
		 (status == TEST_PASS) ? "R" : "Unr", key_id);

end:
	if (unique_id)
		free(unique_id);

	return status;
}

static int find_keys_attrs(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE sess,
			   CK_ULONG nb_max_keys, CK_ATTRIBUTE_PTR attrs,
			   CK_ULONG nb_attrs)
{
	int status = TEST_FAIL;

	int error = 0;
	CK_RV ret = CKR_OK;
	CK_OBJECT_HANDLE_PTR hkeys_match = NULL;
	CK_ULONG hkeys_max = nb_max_keys;
	CK_ULONG nb_keys_match = 0;
	CK_ULONG idx = 0;
	CK_OBJECT_CLASS key_class;
	CK_ATTRIBUTE obj_class[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
	};

	/*
	 * Allocate one more key than expected to check that the number
	 * of keys found are not exceeding expected number.
	 * If the number max of keys to find is 0, try to find at least
	 * one. If find returns one key, there is an error.
	 */
	if (INC_OVERFLOW(hkeys_max, 1))
		goto end;

	hkeys_match = calloc(1, hkeys_max);
	if (CHECK_EXPECTED(hkeys_match, "Allocation error"))
		goto end;

	ret = pfunc->C_FindObjectsInit(sess, attrs, nb_attrs);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, hkeys_match, hkeys_max,
				   &nb_keys_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	if (CHECK_EXPECTED(nb_keys_match == nb_max_keys,
			   "Got %lu but expected %lu objects", nb_keys_match,
			   nb_max_keys))
		error = 1;

	for (idx = 0; idx < nb_max_keys; idx++) {
		if (hkeys_match[idx] == CK_INVALID_HANDLE)
			continue;

		ret = pfunc->C_GetAttributeValue(sess, hkeys_match[idx],
						 obj_class,
						 ARRAY_SIZE(obj_class));
		if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue")) {
			error = 1;
			continue;
		}

		switch (key_class) {
		case CKO_PUBLIC_KEY:
			status = check_public_keys(pfunc, sess,
						   hkeys_match[idx]);
			break;

		case CKO_PRIVATE_KEY:
			status = check_private_keys(pfunc, sess,
						    hkeys_match[idx]);
			break;

		case CKO_SECRET_KEY:
			status = check_secret_keys(pfunc, sess,
						   hkeys_match[idx]);
			break;

		default:
			status = TEST_FAIL;
		}

		if (status == TEST_FAIL)
			error = 1;
	}

	status = error ? TEST_FAIL : TEST_PASS;

end:
	if (hkeys_match)
		free(hkeys_match);

	return status;
}

static int find_all_keys(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE sess)
{
	int status = TEST_FAIL;

	int error = 0;
	CK_ULONG nb_max_keys = 0;
	CK_ULONG idx = 0;
	CK_ULONG idx_class = 0;
	CK_OBJECT_CLASS key_classes[] = { CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
					  CKO_SECRET_KEY };
	CK_OBJECT_CLASS key_class = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
	};

	SUBTEST_START();

	for (; idx_class < ARRAY_SIZE(key_classes); idx_class++) {
		nb_max_keys = 0;

		key_class = key_classes[idx_class];

		/* Get the number of keys of the class wanted */
		for (idx = 0; idx < ARRAY_SIZE(objects_key); idx++) {
			switch (key_class) {
			case CKO_PUBLIC_KEY:
				if (!objects_key[idx].is_public)
					continue;

				break;

			case CKO_PRIVATE_KEY:
				if (!objects_key[idx].is_private)
					continue;

				break;

			case CKO_SECRET_KEY:
				if (!objects_key[idx].is_secret)
					continue;

				break;

			default:
				error = 1;
				goto end;
			}

			if (INC_OVERFLOW(nb_max_keys, 1)) {
				error = 1;
				goto end;
			}
		}

		TEST_OUT("Find all keys\n");

		status = find_keys_attrs(pfunc, sess, nb_max_keys, match_attrs,
					 ARRAY_SIZE(match_attrs));
		if (status == TEST_FAIL)
			error = 1;
	}

end:
	status = error ? TEST_FAIL : TEST_PASS;

	SUBTEST_END(status);
	return status;
}

static int find_all_keys_usage_verify(CK_FUNCTION_LIST_PTR pfunc,
				      CK_SESSION_HANDLE sess)
{
	int status = TEST_FAIL;

	int error = 0;
	CK_ULONG nb_max_keys = 0;
	CK_ULONG idx = 0;
	CK_ULONG idx_class = 0;
	CK_OBJECT_CLASS key_classes[] = { CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
					  CKO_SECRET_KEY };
	CK_BBOOL btrue = CK_TRUE;
	CK_OBJECT_CLASS key_class = 0;
	CK_ATTRIBUTE match_attrs[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_VERIFY, &btrue, sizeof(btrue) },
	};

	SUBTEST_START();

	if (is_seco_subsystem()) {
		TEST_OUT("Seco doesn't manage key attributes");
		status = TEST_SKIP;
		goto exit;
	}

	for (; idx_class < ARRAY_SIZE(key_classes); idx_class++) {
		nb_max_keys = 0;

		key_class = key_classes[idx_class];

		/* Get the number of public keys where verify flag is set */
		for (idx = 0; idx < ARRAY_SIZE(objects_key); idx++) {
			switch (key_class) {
			case CKO_PUBLIC_KEY:
				if (objects_key[idx].is_public &&
				    objects_key[idx].p11_key.verify) {
					if (INC_OVERFLOW(nb_max_keys, 1)) {
						error = 1;
						goto end;
					}
				}

				break;

			case CKO_SECRET_KEY:
				if (objects_key[idx].is_secret &&
				    objects_key[idx].p11_key.verify) {
					if (INC_OVERFLOW(nb_max_keys, 1)) {
						error = 1;
						goto end;
					}
				}
				break;

			default:
				break;
			}
		}

		TEST_OUT("Find all keys where usage is VERIFY\n");
		status = find_keys_attrs(pfunc, sess, nb_max_keys, match_attrs,
					 ARRAY_SIZE(match_attrs));
		if (status == TEST_FAIL)
			error = 1;
	}

end:
	status = error ? TEST_FAIL : TEST_PASS;

exit:
	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_find_ext(void *lib_hdl, CK_VOID_PTR pfunc)
{
	(void)lib_hdl;

	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_C_INITIALIZE_ARGS init = { 0 };
	CK_FUNCTION_LIST_PTR pfunc_list = pfunc;

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START();

	ret = pfunc_list->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	if (generate_objects_key(pfunc) == TEST_FAIL)
		goto end;

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc_list->C_Login(sess, CKU_USER, NULL_PTR, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	if (find_all_keys(pfunc, sess) == TEST_FAIL)
		goto end;

	status = find_all_keys_usage_verify(pfunc, sess);

end:
	delete_objects_key();

	util_close_session(pfunc, &sess);

	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}
