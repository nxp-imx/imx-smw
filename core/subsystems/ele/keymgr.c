// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "keymgr_attest.h"
#include "object_query.h"

#include "key_group.h"

static unsigned int ecc_public_key_length(unsigned int security_size);
static unsigned int ed_public_key_length(unsigned int security_size);
static unsigned int ed448_public_key_length(unsigned int security_size);
static unsigned int rsa_public_key_length(unsigned int security_size);
static unsigned int rsa_modulus_length(unsigned int security_size);

/*
 * Bit mask identifing the key category, asymmetric public, keypair
 * symmetric key and raw key.
 */
#define ELE_KEY_CATEGORY_MASK	      ((unsigned int)(BIT(14) | BIT(13) | BIT(12)))
#define ELE_ASYM_KEY_TYPE_MASK	      BIT(14)
#define ELE_ASYM_PUBLIC_KEY_TYPE_MASK BIT(14)
#define ELE_ASYM_KEYPAIR_TYPE_MASK    ((unsigned int)(BIT(14) | BIT(13) | BIT(12)))
#define ELE_SYM_KEY_TYPE_MASK	      BIT(13)
#define ELE_RAW_KEY_TYPE_MASK	      BIT(12)

/*
 * Key lifetime encoding
 */
#define ELE_KEY_TRANSIENT  0x0
#define ELE_KEY_PERSISTENT 0x1
#define ELE_KEY_PERMANENT  0xFF

#define ELE_KEY_LIFETIME_PERSISTENCE_MASK 0xFF
#define ELE_KEY_LIFETIME_PERSISTENCE_GET(val)                                  \
	((val) & (ELE_KEY_LIFETIME_PERSISTENCE_MASK))
#define ELE_KEY_LIFETIME_LOCATION_MASK	0xFFFFFF
#define ELE_KEY_LIFETIME_LOCATION_SHIFT 8
#define ELE_KEY_LIFETIME_LOCATION_GET(val)                                     \
	(((val) >> ELE_KEY_LIFETIME_LOCATION_SHIFT) &                          \
	 ELE_KEY_LIFETIME_LOCATION_MASK)

/*
 * Macro setting the ELE key type category
 */
#define ELE_ASYM_PUBLIC_KEY_TYPE(type)                                         \
	SET_CLEAR_MASK(type, ELE_ASYM_PUBLIC_KEY_TYPE_MASK,                    \
		       ELE_KEY_CATEGORY_MASK)

#define ELE_ASYM_KEYPAIR_KEY_TYPE(type)                                        \
	SET_CLEAR_MASK(type, ELE_ASYM_KEYPAIR_TYPE_MASK, ELE_KEY_CATEGORY_MASK)

#define KEY_DEF(_key_type_id, _key_type, _security_size, _public_length,       \
		_modulus_length)                                               \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.key_type = HSM_KEY_TYPE_##_key_type,                          \
		.security_size = _security_size,                               \
		.public_length = _public_length,                               \
		.modulus_length = _modulus_length                              \
	}

#define KEY_DEF_SYM(_key_type, _security_size)                                 \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type,             \
		.key_type = HSM_KEY_TYPE_##_key_type,                          \
		.security_size = _security_size, .public_length = NULL,        \
		.modulus_length = NULL                                         \
	}

#define KEY_DEF_ECC_NIST(_security_size)                                       \
	KEY_DEF(SECP_R1, ECC_NIST, _security_size, ecc_public_key_length, NULL)

#define KEY_DEF_ECC_BP(_security_size)                                         \
	KEY_DEF(BRAINPOOL_R1, ECC_BP_R1, _security_size,                       \
		ecc_public_key_length, NULL)

#define KEY_DEF_RSA(_security_size)                                            \
	KEY_DEF(RSA, RSA, _security_size, rsa_public_key_length,               \
		rsa_modulus_length)

#define KEY_DEF_EDWARDS_CURVE(_key_type, _security_size, _public_length)       \
	KEY_DEF(_key_type, ECC_TWISTED_EDWARDS, _security_size,                \
		_public_length, NULL)

#define KEY_DEF_MONTGOMERY_CURVE(_key_type, _security_size, _public_length)    \
	KEY_DEF(_key_type, ECC_MONTGOMERY, _security_size, _public_length, NULL)

/**
 * struct key_def - ELE Key definition
 * @key_type_id: SMW key type ID
 * @key_type: ELE full key type ID (keypair, symmetric or raw)
 * @public_length: Function pointer calculating the public key length in bytes
 * @modulus_length: Function pointer calculating the RSA modulus length in bytes
 */
static const struct key_def {
	enum smw_config_key_type_id key_type_id;
	unsigned int key_type;
	unsigned int security_size;
	unsigned int (*public_length)(unsigned int security_size);
	unsigned int (*modulus_length)(unsigned int security_size);
} key_def_list[] = {
	KEY_DEF_ECC_NIST(224),
	KEY_DEF_ECC_NIST(256),
	KEY_DEF_ECC_NIST(384),
	KEY_DEF_ECC_NIST(521),
	KEY_DEF_ECC_BP(224),
	KEY_DEF_ECC_BP(256),
	KEY_DEF_ECC_BP(384),
	KEY_DEF_SYM(AES, 128),
	KEY_DEF_SYM(AES, 192),
	KEY_DEF_SYM(AES, 256),
	KEY_DEF_SYM(HMAC, 224),
	KEY_DEF_SYM(HMAC, 256),
	KEY_DEF_SYM(HMAC, 384),
	KEY_DEF_SYM(HMAC, 512),
	KEY_DEF_RSA(2048),
	KEY_DEF_RSA(3072),
	KEY_DEF_RSA(4096),
	KEY_DEF_EDWARDS_CURVE(ED25519, 255, ed_public_key_length),
	KEY_DEF_EDWARDS_CURVE(ED448, 448, ed448_public_key_length),
	KEY_DEF_MONTGOMERY_CURVE(X25519, 255, ed_public_key_length),
	KEY_DEF_MONTGOMERY_CURVE(X448, 448, ed_public_key_length),
	KEY_DEF(DERIVE, DERIVE, 384, NULL, NULL),
	KEY_DEF(HKDF_IKM, DERIVE, 256, NULL, NULL),
	KEY_DEF(HKDF_IKM, DERIVE, 384, NULL, NULL),
};

#define SIGN_ALGO(_algo_id, _type_id, _hash_id, _sign_algo)                    \
	{                                                                      \
		.algo_id = SMW_CONFIG_SIGN_ALGO_ID_##_algo_id,                 \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_type_id,                 \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_hash_id,                 \
		.algo = HSM_PKEY_ATTEST_ALGO_##_sign_algo                      \
	}

/**
 * struct signature_algo - ELE signature algorithm
 * @algo_id: SMW signature algo ID
 * @type_id: SMW signature type ID
 * @hash_id: SMW signature hash ID
 * @algo: ELE Sign algo ID
 */
static const struct signature_algo {
	enum smw_config_sign_algo_id algo_id;
	enum smw_config_sign_type_id type_id;
	enum smw_config_hash_algo_id hash_id;
	hsm_op_pub_key_attest_algo_t algo;
} signature_algo_list[] = { SIGN_ALGO(DEFAULT, CMAC, INVALID, CMAC),
			    SIGN_ALGO(ECDSA, DEFAULT, SHA224, ECDSA_SHA224),
			    SIGN_ALGO(ECDSA, DEFAULT, SHA256, ECDSA_SHA256),
			    SIGN_ALGO(ECDSA, DEFAULT, SHA384, ECDSA_SHA384),
			    SIGN_ALGO(ECDSA, DEFAULT, SHA512, ECDSA_SHA512) };

static unsigned int ecc_public_key_length(unsigned int security_size)
{
	return BITS_TO_BYTES_SIZE(security_size) * 2;
}

static unsigned int ed_public_key_length(unsigned int security_size)
{
	return BITS_TO_BYTES_SIZE(security_size);
}

static unsigned int ed448_public_key_length(unsigned int security_size)
{
	return BITS_TO_BYTES_SIZE(security_size) + 1;
}

static unsigned int rsa_public_key_length(unsigned int security_size)
{
	(void)security_size;

	/* RSA public exponent is hardcoded to be 65537 */
	return DEFAULT_RSA_PUB_EXP_LEN;
}

static unsigned int rsa_modulus_length(unsigned int security_size)
{
	return BITS_TO_BYTES_SIZE(security_size);
}

static const struct key_def *
get_key_def_by_smw_type(enum smw_config_key_type_id key_type_id)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_def_list);
	const struct key_def *key = key_def_list;
	const struct key_def *ret_key = NULL;

	for (; i < size; i++, key++) {
		if (key->key_type_id == key_type_id) {
			ret_key = key;
			break;
		}
	}

	return ret_key;
}

static const struct key_def *get_key_def_by_ele_type(unsigned int key_type,
						     unsigned int security_size)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_def_list);
	const struct key_def *key = key_def_list;
	const struct key_def *ret_key = NULL;

	unsigned int full_key_type = key_type;

	if (key_type & ELE_ASYM_KEY_TYPE_MASK)
		full_key_type = ELE_ASYM_KEYPAIR_KEY_TYPE(key_type);

	for (; i < size; i++, key++) {
		if (key->key_type == full_key_type &&
		    key->security_size == security_size) {
			ret_key = key;
			break;
		}
	}

	return ret_key;
}

static void get_key_privacy_by_ele_type(unsigned int key_type,
					enum smw_keymgr_privacy_id *privacy)
{
	*privacy = SMW_KEYMGR_PRIVACY_ID_PRIVATE;

	if (key_type & ELE_ASYM_KEYPAIR_TYPE_MASK)
		*privacy = SMW_KEYMGR_PRIVACY_ID_PAIR;
	else if (key_type & ELE_ASYM_PUBLIC_KEY_TYPE_MASK)
		*privacy = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
}

int ele_get_key_type(enum smw_config_key_type_id key_type_id,
		     hsm_key_type_t *ele_key_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	const struct key_def *key_def = NULL;
	unsigned int key_type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_def = get_key_def_by_smw_type(key_type_id);
	if (key_def) {
		key_type = key_def->key_type;
		if (!SET_OVERFLOW(key_type, *ele_key_type))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void get_key_persistence(hsm_key_lifetime_t lifetime,
				smw_attr_attributes_t *attributes)
{
	switch (ELE_KEY_LIFETIME_PERSISTENCE_GET(lifetime)) {
	case ELE_KEY_TRANSIENT:
		*attributes = SMW_ATTR_SET_TRANSIENT(*attributes);
		break;

	case ELE_KEY_PERSISTENT:
		*attributes = SMW_ATTR_SET_PERSISTENT(*attributes);
		break;

	case ELE_KEY_PERMANENT:
		*attributes = SMW_ATTR_SET_PERMANENT(*attributes);
		break;

	default:
		break;
	}
}

static int set_sign_algo(struct smw_sign_verify_attributes *attributes,
			 hsm_op_pub_key_attest_algo_t *algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(signature_algo_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (signature_algo_list[i].algo_id == attributes->algo_id &&
		    signature_algo_list[i].type_id == attributes->type_id &&
		    signature_algo_list[i].hash_id == attributes->hash_id) {
			*algo = signature_algo_list[i].algo;

			SMW_DBG_PRINTF(DEBUG, "ELE signature algorithm: %d\n",
				       *algo);

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * check_export_key_config() - Check key descriptor configuration.
 * @key_descriptor: Pointer to key descriptor.
 *
 * EdgeLock Enclave subsystem only exports public key of an asymmetric key.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Configuration not supported.
 */
static int check_export_key_config(struct smw_keymgr_descriptor *key_descriptor)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (key_descriptor->identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_SECP_R1:
	case SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ED25519:
	case SMW_CONFIG_KEY_TYPE_ID_X25519:
	case SMW_CONFIG_KEY_TYPE_ID_ED448:
	case SMW_CONFIG_KEY_TYPE_ID_X448:
		if (smw_keymgr_get_public_data(key_descriptor) &&
		    !smw_keymgr_get_private_data(key_descriptor)) {
			status = SMW_STATUS_OK;
			break;
		}

		SMW_DBG_PRINTF(ERROR, "%s: ELE only exports public key\n",
			       __func__);
		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		if (smw_keymgr_get_modulus(key_descriptor) &&
		    !smw_keymgr_get_private_data(key_descriptor)) {
			status = SMW_STATUS_OK;
			break;
		}

		SMW_DBG_PRINTF(ERROR, "%s: ELE only exports public modulus\n",
			       __func__);
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "%s: Key type %d not exportable",
			       __func__, key_descriptor->identifier.type_id);
		break;
	}

	return status;
}

int open_key_mgmt_service(struct hdl *hdl, hsm_hdl_t *key_management_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;
	open_svc_key_management_args_t open_svc_key_management_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_key_management_service(hdl->key_store,
					      &open_svc_key_management_args,
					      key_management_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
	SMW_DBG_PRINTF(DEBUG, "Open key_management_hdl: %u\n",
		       *key_management_hdl);

	return ele_convert_err(err);
}

int close_key_mgt_service(hsm_hdl_t key_management_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Close key_management_hdl: %u\n",
		       key_management_hdl);

	if (key_management_hdl) {
		err = hsm_close_key_management_service(key_management_hdl);
		SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
	}

	return ele_convert_err(err);
}

static int delete_key_operation(hsm_hdl_t key_mgt_hdl,
				struct smw_keymgr_identifier *key_identifier)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	op_delete_key_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.key_identifier = key_identifier->s_id;
	if (SMW_ATTR_IS_PERSISTENT(key_identifier->key_attributes.attributes) ||
	    SMW_ATTR_IS_PERMANENT(key_identifier->key_attributes.attributes))
		op_args.flags = HSM_OP_DEL_KEY_FLAGS_STRICT_OPERATION;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_delete_key()\n"
		       "  key_management_hdl: %u\n"
		       "  op_delete_key_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    flags: 0x%X\n",
		       __func__, __LINE__, key_mgt_hdl, op_args.key_identifier,
		       op_args.flags);

	err = hsm_delete_key(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_delete_key returned %d\n", err);

	status = ele_convert_err(err);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_attributes_operation(struct hdl *hdl,
					op_get_key_attr_args_t *key_attrs)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_get_key_attr()\n"
		       "  key_management_hdl: %u\n"
		       "  op_get_key_attr_args_t\n"
		       "    key_identifier: 0x%08X\n",
		       __func__, __LINE__, key_mgt_hdl,
		       key_attrs->key_identifier);

	err = hsm_get_key_attr(key_mgt_hdl, key_attrs);
	SMW_DBG_PRINTF(DEBUG, "hsm_get_key_attr returned %d\n", err);

	status = ele_convert_err(err);

end:
	tmp_status = close_key_mgt_service(key_mgt_hdl);

	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int update_export_rsa_key_data(struct smw_keymgr_descriptor *key_desc,
				      unsigned char *modulus_data,
				      unsigned int modulus_length)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	int i = 0;
	unsigned char *public_data = NULL;
	unsigned int public_length = 0;
	unsigned int def_pub_length = DEFAULT_RSA_PUB_EXP_LEN;
	unsigned char def_pub[DEFAULT_RSA_PUB_EXP_LEN] = { 0 };

	public_length = smw_keymgr_get_public_length(key_desc);

	if (modulus_data && public_length >= def_pub_length) {
		if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
			public_data = def_pub;
		else
			public_data = smw_keymgr_get_public_data(key_desc);

		for (; public_data && i < DEFAULT_RSA_PUB_EXP_LEN; i++)
			public_data[i] =
				(DEFAULT_RSA_PUB_EXP >> (i * 8)) & UCHAR_MAX;

		status =
			smw_keymgr_update_modulus_buffer(key_desc, modulus_data,
							 modulus_length);

		tmp_status =
			smw_keymgr_update_public_buffer(key_desc, public_data,
							def_pub_length);

		if (status == SMW_STATUS_OK)
			status = tmp_status;
	} else {
		if (public_length < def_pub_length)
			status = SMW_STATUS_OUTPUT_TOO_SHORT;

		tmp_status = smw_keymgr_update_modulus_buffer(key_desc, NULL,
							      modulus_length);
		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;

		tmp_status = smw_keymgr_update_public_buffer(key_desc, NULL,
							     def_pub_length);
		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

	return status;
}

static int export_key_operation(struct hdl *hdl,
				struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;
	hsm_err_t err = HSM_NO_ERROR;

	op_pub_key_recovery_args_t op_args = { 0 };

	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	enum smw_config_key_type_id key_type_id = key_identifier->type_id;
	unsigned char *public_data = NULL;
	unsigned char *modulus_data = NULL;
	unsigned char *tmp_key = NULL;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_export_key_config(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_type_id != SMW_CONFIG_KEY_TYPE_ID_RSA) {
		/* Set the operation output with user public key arguments */
		public_data = smw_keymgr_get_public_data(key_desc);
		public_length = smw_keymgr_get_public_length(key_desc);

		if (SET_OVERFLOW(public_length, op_args.out_key_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		op_args.out_key = public_data;
	} else {
		/* Set the operation output with user modulus arguments */
		modulus_data = smw_keymgr_get_modulus(key_desc);
		modulus_length = smw_keymgr_get_modulus_length(key_desc);

		if (SET_OVERFLOW(modulus_length, op_args.out_key_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		op_args.out_key = modulus_data;
	}

	if (op_args.out_key &&
	    key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/*
		 * Assume the user buffer length is big enough, ELE subsystem
		 * will return the real public buffer length exported
		 */
		tmp_key = SMW_UTILS_MALLOC(op_args.out_key_size);
		if (!tmp_key) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		op_args.out_key = tmp_key;
	}

	op_args.key_identifier = key_identifier->s_id;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_pub_key_recovery()\n"
		       "  key_store_hdl: %u\n"
		       "  op_pub_key_recovery_args_t\n"
		       "    key identifier: 0x%08X\n"
		       "    Public Key\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, hdl->key_store,
		       op_args.key_identifier, op_args.out_key,
		       op_args.out_key_size);

	err = hsm_pub_key_recovery(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_pub_key_recovery returned %d\n", err);

	status = ele_convert_err(err);

	public_length = op_args.exp_out_key_size;

	if (key_type_id != SMW_CONFIG_KEY_TYPE_ID_RSA) {
		if (status == SMW_STATUS_OK) {
			/*
			 * On i.MX93 and i.MX91, the exported public key buffer
			 * is encoded in big-endian format for ECC Edwards and
			 * Montgomery key pairs.
			 * Hence, convert it to little endian format.
			 */
			status = check_and_convert_endian(op_args.out_key, NULL,
							  public_length,
							  key_type_id);
			if (status != SMW_STATUS_OK) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}

			status =
				smw_keymgr_update_public_buffer(key_desc,
								op_args.out_key,
								public_length);
		} else if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
			tmp_status =
				smw_keymgr_update_public_buffer(key_desc, NULL,
								public_length);
			if (tmp_status != SMW_STATUS_OK)
				status = tmp_status;
		}
	} else {
		if (status == SMW_STATUS_OK) {
			status = update_export_rsa_key_data(key_desc,
							    op_args.out_key,
							    public_length);
		} else if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
			tmp_status = update_export_rsa_key_data(key_desc, NULL,
								public_length);
			if (tmp_status != SMW_STATUS_OK)
				status = tmp_status;
		}
	}

end:
	if (tmp_key)
		SMW_UTILS_FREE(tmp_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_generate_key_args_t op_args = { 0 };

	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	struct smw_key_attributes *key_attributes = NULL;
	unsigned char *public_data = NULL;
	uint32_t key_id = 0;
	unsigned char *tmp_key = NULL;
	unsigned int public_length = 0;
	smw_attr_attributes_t persistence = 0;
	bool persistent_grp = false;
	unsigned int key_group = 0;
	smw_attr_algo_t actual_permitted_algo = 0;
	smw_attr_usage_t actual_usage_flags = SMW_ATTR_USAGE_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_attributes = &key_identifier->key_attributes;

	status = ele_get_key_type(key_identifier->type_id, &op_args.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set the operation public key with user arguments */
	public_data = smw_keymgr_get_public_data(key_desc);
	public_length = smw_keymgr_get_public_length(key_desc);
	if (SET_OVERFLOW(public_length, op_args.out_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.out_key = public_data;

	if (public_data && key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/*
		 * Assume the user buffer length is big enough, ELE subsystem
		 * will return the real public buffer length exported
		 */
		tmp_key = SMW_UTILS_MALLOC(op_args.out_size);
		if (!tmp_key) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		op_args.out_key = tmp_key;
	}

	op_args.key_identifier = &key_id;
	if (SET_OVERFLOW(key_identifier->security_size, op_args.bit_key_sz)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	ele_set_key_policy(&op_args.permitted_algo, &op_args.key_usage,
			   key_attributes->permitted_algo,
			   key_attributes->usage_flags);
	ele_get_key_policy(&actual_permitted_algo, &actual_usage_flags,
			   op_args.permitted_algo, op_args.key_usage);

	persistence = SMW_ATTR_GET_PERSISTENCE(key_attributes->attributes);

	switch (persistence) {
	case SMW_ATTR_PERSISTENCE_PERSISTENT:
		op_args.key_lifetime = HSM_SE_KEY_STORAGE_PERSISTENT;
		/* Force persistent key to be written in NVM */
		op_args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_PERMANENT:
		op_args.key_lifetime = HSM_SE_KEY_STORAGE_PERS_PERM;
		/* Force permanent key to be written in NVM */
		op_args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		op_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		key_group = ELE_FIRST_TRANSIENT_KEY_GROUP;
		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = open_key_mgmt_service(&ele_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	do {
		/*
		 * Set the expected key identifier in case of ELE returns
		 * NVM storage group full. ELE erases the key identifier of
		 * the operation argument.
		 */
		key_id = key_identifier->s_id;

		status = ele_get_key_group(ele_ctx, persistent_grp, &key_group);
		if (status != SMW_STATUS_OK)
			goto end;

		if (SET_OVERFLOW(key_group, op_args.key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_generate_key()\n"
			       "key_management_hdl: %u\n"
			       "op_generate_key_args_t\n"
			       "    flags: 0x%X\n"
			       "    key identifier (%p): 0x%08X\n"
			       "    key policy\n"
			       "      - type: 0x%04X\n"
			       "      - size (bits): %d\n"
			       "      - group: %d\n"
			       "      - lifetime: 0x%X\n"
			       "      - usage: 0x%04X\n"
			       "      - algo: 0x%08X\n"
			       "    Public Key (output)\n"
			       "      - buffer: %p\n"
			       "      - size: %d\n",
			       __func__, __LINE__, key_mgt_hdl, op_args.flags,
			       op_args.key_identifier, *op_args.key_identifier,
			       op_args.key_type, op_args.bit_key_sz,
			       op_args.key_group, op_args.key_lifetime,
			       op_args.key_usage, op_args.permitted_algo,
			       op_args.out_key, op_args.out_size);

		err = hsm_generate_key(key_mgt_hdl, &op_args);
		SMW_DBG_PRINTF(DEBUG, "hsm_generate_key returned %d\n", err);

		if (err == HSM_KEY_GROUP_FULL) {
			status = ele_set_key_group_state(ele_ctx, key_group,
							 persistent_grp, true);
			if (status != SMW_STATUS_OK)
				goto end;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	} while (err == HSM_KEY_GROUP_FULL);

	status = ele_convert_err(err);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status =
			smw_keymgr_update_public_buffer(key_desc, NULL,
							op_args.exp_out_size);

		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier->subsystem_id = SUBSYSTEM_ID_ELE;
	key_identifier->s_id = key_id;
	key_identifier->group = key_group;

	SMW_DBG_PRINTF(DEBUG, "Key identifier: 0x%08X\n", key_id);

	if (public_data) {
		/*
		 * On i.MX93 and i.MX91, the exported public key buffer is encoded
		 * in big-endian format for ECC Edwards and X25519 key pairs. Hence,
		 * Convert it to little endian format.
		 */
		status = check_and_convert_endian(op_args.out_key, NULL,
						  op_args.exp_out_size,
						  key_identifier->type_id);
		if (status != SMW_STATUS_OK) {
			status = SMW_STATUS_OPERATION_FAILURE;

			/*
			 * Delete the key in subsystem as smw_generate_key()
			 * is going to remove it from the key database
			 */
			(void)delete_key_operation(key_mgt_hdl, key_identifier);
			goto end;
		}

		status = smw_keymgr_update_public_buffer(key_desc,
							 op_args.out_key,
							 op_args.exp_out_size);

		if (status != SMW_STATUS_OK) {
			/*
			 * Delete the key in subsystem as smw_generate_key()
			 * is going to remove it from the key database
			 */
			(void)delete_key_operation(key_mgt_hdl, key_identifier);
			goto end;
		}
	}

	if (key_attributes->permitted_algo != actual_permitted_algo) {
		key_attributes->permitted_algo = actual_permitted_algo;

		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

	if (key_attributes->usage_flags != actual_usage_flags) {
		key_attributes->usage_flags = actual_usage_flags;

		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

end:
	tmp_status = close_key_mgt_service(key_mgt_hdl);

	if (status == SMW_STATUS_OK)
		status = tmp_status;

	if (tmp_key)
		SMW_UTILS_FREE(tmp_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}

static int import_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	int tmp_status = SMW_STATUS_OK;
	struct smw_keymgr_import_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = NULL;
	unsigned int storage_id = 0;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_import_key_args_t op_args = { 0 };

	unsigned char *priv_key = NULL;
	unsigned int priv_key_len = 0;
	unsigned char *hex_priv_key = NULL;
	unsigned int hex_priv_key_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = &key_args->key_descriptor;
	storage_id = key_desc->identifier.key_attributes.storage_id;

	priv_key = smw_keymgr_get_private_data(key_desc);
	priv_key_len = smw_keymgr_get_private_length(key_desc);

	if (!priv_key || !priv_key_len) {
		SMW_DBG_PRINTF(ERROR, "Missing import key buffer or length");
		goto end;
	}

	status = smw_keymgr_set_hex_key_buffer(key_desc->format_id, priv_key,
					       priv_key_len, &hex_priv_key,
					       &hex_priv_key_len);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.input_lsb_addr = hex_priv_key;
	op_args.input_size = hex_priv_key_len;

	if (NXP_IS_EL2GO_OBJECT(storage_id))
		op_args.flags = HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV |
				HSM_OP_IMPORT_KEY_FLAGS_STRICT_OPERATION;
	else
		op_args.flags = HSM_OP_IMPORT_KEY_INPUT_ELE_TLV |
				HSM_OP_IMPORT_KEY_FLAGS_STRICT_OPERATION;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_import_key()\n"
		       "  key_store_hdl: 0x%x\n"
		       "  op_import_key_args_t\n"
		       "    Flags: 0x%x\n"
		       "    Key\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, key_mgt_hdl, op_args.flags,
		       op_args.input_lsb_addr, op_args.input_size);

	err = hsm_import_key(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_import_key returned %d\n", err);

	status = ele_convert_err(err);
	if (status == SMW_STATUS_OK) {
		SMW_DBG_PRINTF(DEBUG, "hsm_import_key key id 0x%08X\n",
			       op_args.key_identifier);
		key_desc->identifier.s_id = op_args.key_identifier;
		key_desc->identifier.subsystem_id = SUBSYSTEM_ID_ELE;

		/*
		 * In case of key importation, the key group is unknown.
		 * The FW selects the key group.
		 */
		key_desc->identifier.group = ELE_UNDEFINED_KEY_GROUP;
	}

end:
	if (key_mgt_hdl) {
		tmp_status = close_key_mgt_service(key_mgt_hdl);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && hex_priv_key)
		SMW_UTILS_FREE(hex_priv_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int export_key(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args *key_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = export_key_operation(hdl, &key_args->key_descriptor);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_hdl_t key_mgt_hdl = 0;

	struct smw_keymgr_delete_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;
	smw_attr_attributes_t attributes = 0;
	bool is_transient = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(&ele_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	status = delete_key_operation(key_mgt_hdl, &key_desc->identifier);

	tmp_status = close_key_mgt_service(key_mgt_hdl);

	if (status == SMW_STATUS_OK &&
	    key_desc->identifier.group != ELE_UNDEFINED_KEY_GROUP) {
		status = tmp_status;

		/* Let assume there is place to add a new key */
		attributes = key_desc->identifier.key_attributes.attributes;
		is_transient = SMW_ATTR_IS_TRANSIENT(attributes);

		tmp_status = ele_set_key_group_state(ele_ctx,
						     key_desc->identifier.group,
						     !is_transient, false);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}

static int get_key_lengths(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_desc = NULL;
	op_get_key_attr_args_t key_attrs = { 0 };

	const struct key_def *key_def = NULL;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = args;

	key_attrs.key_identifier = key_desc->identifier.s_id;

	status = get_key_attributes_operation(hdl, &key_attrs);

	if (status == SMW_STATUS_OK) {
		key_def = get_key_def_by_ele_type(key_attrs.key_type,
						  key_attrs.bit_key_sz);
		if (key_def && key_def->public_length)
			public_length =
				key_def->public_length(key_attrs.bit_key_sz);

		if (key_def && key_def->modulus_length)
			modulus_length =
				key_def->modulus_length(key_attrs.bit_key_sz);

		/*
		 * Only public key is available, private or symmetric key
		 * are never exported.
		 *
		 * No need to check if it's an asymmetric key and the
		 * type of the key RSA or not.
		 * Key function setting the buffer length is setup
		 * according to key type.
		 */
		status = smw_keymgr_update_public_buffer(key_desc, NULL,
							 public_length);

		tmp_status = smw_keymgr_update_modulus_buffer(key_desc, NULL,
							      modulus_length);
		if (status == SMW_STATUS_OK)
			status = tmp_status;

		tmp_status =
			smw_keymgr_update_private_buffer(key_desc, NULL, 0);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_attributes(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_get_key_attributes_args *key_args = args;
	struct smw_keymgr_identifier *key_identifier = NULL;
	struct smw_key_attributes *key_attributes = NULL;
	op_get_key_attr_args_t op_key_attrs = { 0 };
	const struct key_def *key_def = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_identifier = &key_args->key_descriptor.identifier;
	key_attributes = &key_identifier->key_attributes;

	op_key_attrs.key_identifier = key_identifier->s_id;

	status = get_key_attributes_operation(hdl, &op_key_attrs);
	if (status != SMW_STATUS_OK)
		goto end;

	key_def = get_key_def_by_ele_type(op_key_attrs.key_type,
					  op_key_attrs.bit_key_sz);
	if (!key_def) {
		status = SMW_STATUS_KEY_INVALID;
		goto end;
	}

	key_identifier->type_id = key_def->key_type_id;
	key_identifier->security_size = op_key_attrs.bit_key_sz;
	get_key_privacy_by_ele_type(op_key_attrs.key_type,
				    &key_identifier->privacy_id);
	ele_get_key_lifecycles(op_key_attrs.lifecycle,
			       &key_identifier->key_attributes.attributes);
	get_key_persistence(op_key_attrs.key_lifetime,
			    &key_identifier->key_attributes.attributes);

	ele_get_key_policy(&key_attributes->permitted_algo,
			   &key_attributes->usage_flags,
			   op_key_attrs.permitted_algo, op_key_attrs.key_usage);
	key_attributes->storage_id =
		ELE_KEY_LIFETIME_LOCATION_GET(op_key_attrs.key_lifetime);
	key_attributes->attributes = key_identifier->key_attributes.attributes;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int commit_key_storage(struct hdl *hdl)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_manage_key_group_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.flags = HSM_OP_MANAGE_KEY_GROUP_FLAGS_MONOTONIC |
			HSM_OP_MANAGE_KEY_GROUP_FLAGS_SYNC_KEYSTORE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_manage_key_group()\n"
		       "  key_management_hdl: %u\n"
		       "  op_manage_key_group_args_t\n"
		       "    key_group: 0x%08X\n"
		       "    flags: 0x%08X\n",
		       __func__, __LINE__, key_mgt_hdl, op_args.key_group,
		       op_args.flags);

	err = hsm_manage_key_group(key_mgt_hdl, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_manage_key_group returned %d\n", err);

	status = ele_convert_err(err);

end:
	tmp_status = close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int key_attestation(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_attest_args *attest_args = args;
	struct smw_keymgr_descriptor *attest_key_descriptor =
		&attest_args->attest_key_descriptor;
	hsm_err_t err = HSM_NO_ERROR;
	op_pub_key_attest_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.key_identifier = attest_args->key_descriptor.identifier.s_id;
	op_args.key_attestation_id = attest_key_descriptor->identifier.s_id;

	status = set_sign_algo(&attest_args->sign_attributes,
			       &op_args.attest_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.auth_challenge = smw_keymgr_get_attest_chal(attest_args);
	op_args.auth_challenge_size =
		smw_keymgr_get_attest_chal_length(attest_args);
	op_args.certificate = smw_keymgr_get_attest_cert(attest_args);
	op_args.certificate_size =
		smw_keymgr_get_attest_cert_length(attest_args);

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_do_pub_key_attest()\n"
		       "  key_store_hdl: %u\n"
		       "  op_pub_key_attest_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    key_attestation_id: 0x%08X\n"
		       "    attest_algo: 0x%08X\n"
		       "    Challenge\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Certificate\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, hdl->key_store,
		       op_args.key_identifier, op_args.key_attestation_id,
		       op_args.attest_algo, op_args.auth_challenge,
		       op_args.auth_challenge_size, op_args.certificate,
		       op_args.certificate_size);

	err = hsm_do_pub_key_attest(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_do_pub_key_attest returned %d\n", err);

	status = ele_convert_err(err);

	/* Update certificate length */
	smw_keymgr_set_attest_cert_length(attest_args,
					  op_args.exp_certificate_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static bool key_is_present(struct hdl *hdl, void *args, int *status)
{
	struct smw_object_query *obj_query = args;
	bool handled = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (obj_query->type == SMW_QUERY_TYPE_KEY) {
		*status = get_key_attributes(hdl, obj_query->key);
		handled = true;
	}

	SMW_DBG_PRINTF_COND(VERBOSE, handled, "%s returned %d\n", __func__,
			    *status);
	return handled;
}

int ele_set_pubkey_type(enum smw_config_key_type_id key_type_id,
			hsm_pubkey_type_t *ele_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	const struct key_def *key_def = NULL;
	unsigned int type = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_def = get_key_def_by_smw_type(key_type_id);
	if (key_def) {
		type = ELE_ASYM_PUBLIC_KEY_TYPE(key_def->key_type);
		if (!SET_OVERFLOW(type, *ele_type))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_export_public_key(struct hdl *hdl,
			  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	unsigned int public_length = 0;
	unsigned int modulus_length = 0;
	op_get_key_attr_args_t key_attrs = { 0 };
	const struct key_def *key_def = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* First get the key attributes */
	key_attrs.key_identifier = key_desc->identifier.s_id;
	status = get_key_attributes_operation(hdl, &key_attrs);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get the ELE key definition */
	key_def = get_key_def_by_ele_type(key_attrs.key_type,
					  key_attrs.bit_key_sz);
	if (!key_def) {
		SMW_DBG_PRINTF(VERBOSE,
			       "%s: ELE key type 0x%08x not supported\n",
			       __func__, key_attrs.key_type);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	if (!key_def->public_length) {
		SMW_DBG_PRINTF(VERBOSE, "%s: No public key\n", __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_desc->identifier.type_id = key_def->key_type_id;
	key_desc->identifier.security_size = key_attrs.bit_key_sz;
	key_desc->format_id = SMW_KEYMGR_FORMAT_ID_HEX;

	public_length = key_def->public_length(key_attrs.bit_key_sz);

	/* In case of RSA key modulus is exported too */
	if (key_def->modulus_length)
		modulus_length = key_def->modulus_length(key_attrs.bit_key_sz);

	/* Allocate key descriptor's keypair buffer and its public data */
	status = smw_keymgr_alloc_keypair_buffer(key_desc, public_length, 0,
						 modulus_length);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Export the public key */
	status = export_key_operation(hdl, key_desc);

end:
	if (status != SMW_STATUS_OK && key_desc->pub)
		(void)smw_keymgr_free_keypair_buffer(key_desc);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_key_handle(struct subsystem_context *ele_ctx,
		    enum operation_id operation_id, void *args, int *status)
{
	struct hdl *hdl = NULL;

	SMW_DBG_ASSERT(ele_ctx && args);

	hdl = &ele_ctx->hdl;

	switch (operation_id) {
	case OPERATION_ID_GENERATE_KEY:
		*status = generate_key(ele_ctx, args);
		break;
	case OPERATION_ID_DERIVE_KEY:
		*status = ele_derive_key(ele_ctx, args);
		break;
	case OPERATION_ID_IMPORT_KEY:
		*status = import_key(hdl, args);
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = export_key(hdl, args);
		break;
	case OPERATION_ID_DELETE_KEY:
		*status = delete_key(ele_ctx, args);
		break;
	case OPERATION_ID_GET_KEY_LENGTHS:
		*status = get_key_lengths(hdl, args);
		break;
	case OPERATION_ID_GET_KEY_ATTRIBUTES:
		*status = get_key_attributes(hdl, args);
		break;
	case OPERATION_ID_COMMIT_KEY_STORAGE:
		*status = commit_key_storage(hdl);
		break;
	case OPERATION_ID_KEY_ATTESTATION:
		*status = key_attestation(hdl, args);
		break;
	case OPERATION_ID_IS_OBJECT_PRESENT:
		return key_is_present(hdl, args, status);
	default:
		return false;
	}

	return true;
}
