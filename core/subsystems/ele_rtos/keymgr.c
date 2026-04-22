// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
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
#include "ele_crypto_key_mgr.h"
#include "ele_crypto_key_group_mng.h"

static unsigned int ecc_public_key_length(unsigned int security_size);
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
#define ELE_KEY_PERMANENT  (0x80 | ELE_KEY_PERSISTENT)

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
		.key_type = KEYTYPE_##_key_type,                               \
		.security_size = _security_size,                               \
		.public_length = _public_length,                               \
		.modulus_length = _modulus_length                              \
	}

#define KEY_DEF_SYM(_key_type, _security_size)                                 \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type,             \
		.key_type = KEYTYPE_##_key_type,                               \
		.security_size = _security_size, .public_length = NULL,        \
		.modulus_length = NULL                                         \
	}

#define KEY_DEF_ECC_NIST(_security_size)                                       \
	KEY_DEF(SECP_R1, ECC_KEY_PAIR_SECP_R1_NIST, _security_size,            \
		ecc_public_key_length, NULL)

#define KEY_DEF_ECC_BP(_security_size)                                         \
	KEY_DEF(BRAINPOOL_R1, ECC_KEY_PAIR_BRAINPOOL_R1, _security_size,       \
		ecc_public_key_length, NULL)

#define KEY_DEF_RSA(_security_size)                                            \
	KEY_DEF(RSA, RSA_KEY_PAIR, _security_size, rsa_public_key_length,      \
		rsa_modulus_length)

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
	KEY_DEF(DERIVE, DERIVE, 384, NULL, NULL),
	KEY_DEF(HKDF_IKM, DERIVE, 256, NULL, NULL),
	KEY_DEF(HKDF_IKM, DERIVE, 384, NULL, NULL),
};

static unsigned int ecc_public_key_length(unsigned int security_size)
{
	return BITS_TO_BYTES_SIZE(security_size) * 2;
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

static void get_key_privacy_by_ele_type(unsigned int type,
					enum smw_keymgr_privacy_id *privacy)
{
	*privacy = SMW_KEYMGR_PRIVACY_ID_PRIVATE;

	if ((type & ELE_ASYM_KEYPAIR_TYPE_MASK) == ELE_ASYM_KEYPAIR_TYPE_MASK)
		*privacy = SMW_KEYMGR_PRIVACY_ID_PAIR;
	else if ((type & ELE_ASYM_PUBLIC_KEY_TYPE_MASK) ==
		 ELE_ASYM_PUBLIC_KEY_TYPE_MASK)
		*privacy = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
}

int ele_get_key_type(enum smw_config_key_type_id key_type_id,
		     key_type_t *ele_key_type)
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

static void get_key_persistence(key_lifetime_t lifetime,
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

int open_key_mgmt_service(struct hdl *hdl, uint32_t *key_management_hdl)
{
	int status = SMW_STATUS_OK;

	status_t err = STATUS_SUCCESS;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = ele_open_key_store_service(hdl);
	if (status != SMW_STATUS_OK)
		return status;

	err = ele_open_key_service(hdl->mu_base, hdl->key_store,
				   key_management_hdl);
	SMW_DBG_PRINTF(DEBUG, "ele_open_key_service returned %d\n", err);
	SMW_DBG_PRINTF(DEBUG, "Open key_management_hdl: %u\n",
		       *key_management_hdl);

	// coverity[missing_unlock]
	return ele_convert_err(err);
}

int close_key_mgt_service(struct hdl *hdl, uint32_t key_management_hdl)
{
	status_t err = STATUS_SUCCESS;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Close key_management_hdl: %u\n",
		       key_management_hdl);

	if (key_management_hdl) {
		err = ele_close_key_service(hdl->mu_base, key_management_hdl);
		SMW_DBG_PRINTF(DEBUG, "ele_close_key_service returned %d\n",
			       err);
	}

	return ele_convert_err(err);
}

static int delete_key_operation(struct hdl *hdl, uint32_t key_mgt_hdl,
				struct smw_keymgr_identifier *key_identifier)
{
	int status = SMW_STATUS_OK;
	bool sync = false;

	status_t err = STATUS_SUCCESS;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (SMW_ATTR_IS_PERSISTENT(key_identifier->key_attributes.attributes) ||
	    SMW_ATTR_IS_PERMANENT(key_identifier->key_attributes.attributes))
		sync = true;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call ele_delete_key()\n"
		       "  key_management_hdl: %u\n"
		       "    key_identifier: 0x%08X\n",
		       __func__, __LINE__, key_mgt_hdl, key_identifier->s_id);

	err = ele_delete_key(hdl->mu_base, key_mgt_hdl, key_identifier->s_id,
			     false, sync);
	SMW_DBG_PRINTF(DEBUG, "ele_delete_key returned %d\n", err);

	status = ele_convert_err(err);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_attributes_operation(struct hdl *hdl, uint32_t keyID,
					ele_key_attribute_t *key_attrs)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	status_t err = STATUS_SUCCESS;
	uint32_t key_mgt_hdl = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call ele_get_key_attribute()\n"
		       "  key_management_hdl: %u\n"
		       "    key_identifier: 0x%08X\n",
		       __func__, __LINE__, key_mgt_hdl, keyID);

	err = ele_get_key_attribute(hdl->mu_base, key_mgt_hdl, keyID,
				    key_attrs);
	SMW_DBG_PRINTF(DEBUG, "ele_get_key_attribute returned %d\n", err);

	status = ele_convert_err(err);

end:
	tmp_status = close_key_mgt_service(hdl, key_mgt_hdl);

	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}

static int export_key_operation(struct subsystem_context *ele_ctx,
				struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	status_t err = STATUS_SUCCESS;
	uint32_t key_mgt_hdl = 0;
	ele_gen_key_t gen_key = { 0 };

	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	struct smw_key_attributes *key_attributes = NULL;
	unsigned char *public_data = NULL;
	uint32_t key_id = 0;
	uint16_t key_size = 0;
	unsigned char *tmp_key = NULL;
	unsigned int public_length = 0;
	smw_attr_attributes_t persistence = 0;
	bool persistent_grp = false;
	unsigned int key_group = 0;
	smw_attr_algo_t actual_permitted_algo = 0;
	smw_attr_usage_t actual_usage_flags = SMW_ATTR_USAGE_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_attributes = &key_identifier->key_attributes;

	status = ele_get_key_type(key_identifier->type_id, &gen_key.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set the operation public key with user arguments */
	public_data = smw_keymgr_get_public_data(key_desc);
	public_length = smw_keymgr_get_public_length(key_desc);
	if (SET_OVERFLOW(public_length, gen_key.pub_key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	gen_key.pub_key_addr = public_data;

	if (public_data && key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/*
		 * Assume the user buffer length is big enough, ELE subsystem
		 * will return the real public buffer length exported
		 */
		tmp_key = SMW_UTILS_MALLOC(gen_key.pub_key_size);
		if (!tmp_key) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		gen_key.pub_key_addr = tmp_key;
	}

	gen_key.key_id = key_id;
	if (SET_OVERFLOW(key_identifier->security_size, gen_key.key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	ele_set_key_policy(&gen_key.permitted_alg, &gen_key.key_usage,
			   key_attributes->permitted_algo,
			   key_attributes->usage_flags);
	ele_get_key_policy(&actual_permitted_algo, &actual_usage_flags,
			   gen_key.permitted_alg, gen_key.key_usage);

	persistence = SMW_ATTR_GET_PERSISTENCE(key_attributes->attributes);

	switch (persistence) {
	case SMW_ATTR_PERSISTENCE_PERSISTENT:
		gen_key.key_lifetime = KEY_PERSISTENT;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_PERMANENT:
		gen_key.key_lifetime = KEY_PERSISTENT_PERMANENT;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		gen_key.key_lifetime = KEY_VOLATILE;
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

		if (SET_OVERFLOW(key_group, gen_key.key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call ele_generate_key()\n"
			       "key_management_hdl: %u\n"
			       "    key identifier: 0x%08X\n"
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
			       __func__, __LINE__, key_mgt_hdl, gen_key.key_id,
			       gen_key.key_type, gen_key.key_size,
			       gen_key.key_group, gen_key.key_lifetime,
			       gen_key.key_usage, gen_key.permitted_alg,
			       gen_key.pub_key_addr, gen_key.pub_key_size);

		err = ele_generate_key(ele_ctx->hdl.mu_base, key_mgt_hdl,
				       &gen_key, &key_id, &key_size, false,
				       true);
		SMW_DBG_PRINTF(DEBUG, "ele_generate_key returned %d\n", err);

		if (err == STATUS_ELE_KEY_GROUP_FULL) {
			status = ele_set_key_group_state(ele_ctx, key_group,
							 persistent_grp, true);
			if (status != SMW_STATUS_OK)
				goto end;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	} while (err == STATUS_ELE_KEY_GROUP_FULL);

	status = ele_convert_err(err);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status = smw_keymgr_update_public_buffer(key_desc, NULL,
							     key_size);

		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

	if (status != SMW_STATUS_OK)
		goto end;

	key_identifier->subsystem_id = SUBSYSTEM_ID_ELE;
	key_identifier->s_id = key_id;
	key_identifier->group = key_group;

	SMW_DBG_PRINTF(DEBUG, "Key identifier: 0x%08X\n", key_id);

	if (key_identifier->privacy_id != SMW_KEYMGR_PRIVACY_ID_PUBLIC)
		key_attributes->attributes =
			SMW_ATTR_SET_SENSITIVE(key_attributes->attributes);

	if (public_data) {
		/*
		 * On some device (e.g. i.MX93 and i.MX91), the
		 * exported public key buffer is encoded in big-endian
		 * format for ECC Edwards and Mongomery key. Hence,
		 * convert it to little endian format.
		 */
		status = check_and_convert_endian(ele_ctx, gen_key.pub_key_addr,
						  NULL, key_size,
						  key_identifier->type_id);
		if (status != SMW_STATUS_OK) {
			status = SMW_STATUS_OPERATION_FAILURE;

			/*
			 * Delete the key in subsystem as smw_generate_key()
			 * is going to remove it from the key database
			 */
			(void)delete_key_operation(&ele_ctx->hdl, key_mgt_hdl,
						   key_identifier);
			goto end;
		}

		status = smw_keymgr_update_public_buffer(key_desc,
							 gen_key.pub_key_addr,
							 key_size);

		if (status != SMW_STATUS_OK) {
			/*
			 * Delete the key in subsystem as smw_generate_key()
			 * is going to remove it from the key database
			 */
			(void)delete_key_operation(&ele_ctx->hdl, key_mgt_hdl,
						   key_identifier);
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
	tmp_status = close_key_mgt_service(&ele_ctx->hdl, key_mgt_hdl);

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
	ele_import_key_option_t import_key_option = IMPORT_KEY_OPTION_ELE;

	status_t err = STATUS_SUCCESS;
	uint32_t key_mgt_hdl = 0;
	uint32_t key_id = 0;

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

	status = smw_utils_key_set_hex_buffer(key_desc->format_id, priv_key,
					      priv_key_len, &hex_priv_key,
					      &hex_priv_key_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (NXP_IS_EL2GO_OBJECT(storage_id))
		import_key_option = IMPORT_KEY_OPTION_EL2GO;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call ele_import_key()\n"
		       "  key_store_hdl: 0x%x\n"
		       "    Flags: 0x%x\n"
		       "    Key\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, key_mgt_hdl, import_key_option,
		       hex_priv_key, hex_priv_key_len);

	err = ele_import_key(hdl->mu_base, key_mgt_hdl, hex_priv_key,
			     hex_priv_key_len, true, 0, import_key_option, true,
			     false, &key_id);
	SMW_DBG_PRINTF(DEBUG, "ele_import_key returned %d\n", err);

	status = ele_convert_err(err);
	if (status == SMW_STATUS_OK) {
		SMW_DBG_PRINTF(DEBUG, "ele_import_key key id 0x%08X\n", key_id);
		key_desc->identifier.s_id = key_id;
		key_desc->identifier.subsystem_id = SUBSYSTEM_ID_ELE;

		/*
		 * In case of key importation, ELE select the key group.
		 */
		key_desc->identifier.group = ELE_UNDEFINED_KEY_GROUP;
	}

end:
	if (key_mgt_hdl) {
		tmp_status = close_key_mgt_service(hdl, key_mgt_hdl);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && hex_priv_key)
		SMW_UTILS_FREE(hex_priv_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}

static int export_key(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args *key_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = export_key_operation(ele_ctx, &key_args->key_descriptor);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	uint32_t key_mgt_hdl = 0;

	struct smw_keymgr_delete_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_desc = &key_args->key_descriptor;
	smw_attr_attributes_t attributes = 0;
	bool is_transient = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(&ele_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	status = delete_key_operation(&ele_ctx->hdl, key_mgt_hdl,
				      &key_desc->identifier);

	tmp_status = close_key_mgt_service(&ele_ctx->hdl, key_mgt_hdl);

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
	ele_key_attribute_t key_attrs = { 0 };

	const struct key_def *key_def = NULL;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = args;

	status = get_key_attributes_operation(hdl, key_desc->identifier.s_id,
					      &key_attrs);

	if (status == SMW_STATUS_OK) {
		key_def = get_key_def_by_ele_type(key_attrs.key_type,
						  key_attrs.key_size);
		if (key_def && key_def->public_length)
			public_length =
				key_def->public_length(key_attrs.key_size);

		if (key_def && key_def->modulus_length)
			modulus_length =
				key_def->modulus_length(key_attrs.key_size);

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
	// coverity[missing_unlock]
	return status;
}

static int commit_key_storage(struct hdl *hdl)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	status_t err = STATUS_SUCCESS;
	uint32_t key_mgt_hdl = 0;
	key_group_mng_t operation = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	operation = SYNC_MONOTONIC | SYNC_OP_NO_KEY;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call ele_manage_key_group()\n"
		       "  key_management_hdl: %u\n"
		       "    flags: 0x%08X\n",
		       __func__, __LINE__, key_mgt_hdl, operation);

	err = ele_manage_key_group(hdl->mu_base, key_mgt_hdl, 0, operation,
				   NULL, 0);
	SMW_DBG_PRINTF(DEBUG, "ele_manage_key_group returned %d\n", err);

	status = ele_convert_err(err);

end:
	tmp_status = close_key_mgt_service(hdl, key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}

static bool key_is_present(struct hdl *hdl, void *args, int *status)
{
	struct smw_keymgr_get_key_attributes_args key_attr = { 0 };
	struct smw_object_query *obj_query = args;
	bool handled = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (obj_query->key && obj_query->type == SMW_QUERY_TYPE_KEY) {
		key_attr.key_descriptor = *obj_query->key;
		*status = ele_get_key_attributes(hdl, &key_attr);
		if (*status == SMW_STATUS_OK)
			*obj_query->key = key_attr.key_descriptor;

		handled = true;
	}

	SMW_DBG_PRINTF_COND(VERBOSE, handled, "%s returned %d\n", __func__,
			    *status);
	// coverity[missing_unlock]
	return handled;
}

int ele_get_key_attributes(struct hdl *hdl,
			   struct smw_keymgr_get_key_attributes_args *key_args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier *key_identifier = NULL;
	struct smw_key_attributes *key_attributes = NULL;
	ele_key_attribute_t key_attrs = { 0 };
	key_lifetime_t key_lifetime = 0;
	key_lifecycle_t key_lifecycle = 0;
	key_usage_t key_usage = 0;
	key_permitted_alg_t key_permitted_alg = 0;
	const struct key_def *key_def = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_identifier = &key_args->key_descriptor.identifier;
	key_attributes = &key_identifier->key_attributes;

	status = get_key_attributes_operation(hdl, key_identifier->s_id,
					      &key_attrs);
	if (status != SMW_STATUS_OK)
		goto end;

	key_def =
		get_key_def_by_ele_type(key_attrs.key_type, key_attrs.key_size);
	if (!key_def) {
		status = SMW_STATUS_KEY_INVALID;
		goto end;
	}

	if (SET_OVERFLOW(key_attrs.key_lifetime, key_lifetime) ||
	    SET_OVERFLOW(key_attrs.key_lifecycle, key_lifecycle) ||
	    SET_OVERFLOW(key_attrs.key_usage, key_usage) ||
	    SET_OVERFLOW(key_attrs.permitted_alg, key_permitted_alg)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	key_identifier->type_id = key_def->key_type_id;
	key_identifier->security_size = key_attrs.key_size;
	get_key_privacy_by_ele_type(key_attrs.key_type,
				    &key_identifier->privacy_id);
	ele_get_key_lifecycles(key_lifecycle,
			       &key_identifier->key_attributes.attributes);
	get_key_persistence(key_lifetime,
			    &key_identifier->key_attributes.attributes);
	ele_get_key_policy(&key_attributes->permitted_algo,
			   &key_attributes->usage_flags, key_permitted_alg,
			   key_usage);
	key_attributes->storage_id =
		ELE_KEY_LIFETIME_LOCATION_GET(key_attrs.key_lifetime);
	key_attributes->attributes = key_identifier->key_attributes.attributes;

	if (key_identifier->privacy_id != SMW_KEYMGR_PRIVACY_ID_PUBLIC)
		key_attributes->attributes =
			SMW_ATTR_SET_SENSITIVE(key_attributes->attributes);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}

int ele_set_pubkey_type(enum smw_config_key_type_id key_type_id,
			key_type_t *ele_type)
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

int ele_export_public_key(struct subsystem_context *ele_ctx,
			  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	unsigned int public_length = 0;
	unsigned int modulus_length = 0;
	ele_key_attribute_t key_attrs = { 0 };
	const struct key_def *key_def = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* First get the key attributes */
	status = get_key_attributes_operation(&ele_ctx->hdl,
					      key_desc->identifier.s_id,
					      &key_attrs);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get the ELE key definition */
	key_def =
		get_key_def_by_ele_type(key_attrs.key_type, key_attrs.key_size);
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
	key_desc->identifier.security_size = key_attrs.key_size;
	key_desc->format_id = SMW_KEYMGR_FORMAT_ID_HEX;

	public_length = key_def->public_length(key_attrs.key_size);

	/* In case of RSA key modulus is exported too */
	if (key_def->modulus_length)
		modulus_length = key_def->modulus_length(key_attrs.key_size);

	/* Allocate key descriptor's keypair buffer and its public data */
	status = smw_keymgr_alloc_keypair_buffer(key_desc, public_length, 0,
						 modulus_length);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Export the public key */
	status = export_key_operation(ele_ctx, key_desc);

end:
	if (status != SMW_STATUS_OK && key_desc->pub)
		(void)smw_keymgr_free_keypair_buffer(key_desc);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}

int is_rsa_pub_expo_default(struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *hex_pub_data = NULL;
	unsigned int hex_pub_len = 0;
	unsigned char *public_data = NULL;
	unsigned int public_len = 0;
	unsigned int i = 0;

	public_len = smw_keymgr_get_public_length(key_desc);
	public_data = smw_keymgr_get_public_data(key_desc);
	if (!public_data || !public_len)
		goto end;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id, public_data,
					      public_len, &hex_pub_data,
					      &hex_pub_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (hex_pub_len != DEFAULT_RSA_PUB_EXP_LEN) {
		status = SMW_STATUS_PUBLIC_EXPONENT_NOT_SUPPORTED;
		SMW_DBG_PRINTF(DEBUG, "Unsupported RSA public exponent.\n");
		goto end;
	}

	for (; i < DEFAULT_RSA_PUB_EXP_LEN; i++) {
		if (hex_pub_data[i] !=
		    ((DEFAULT_RSA_PUB_EXP >> (i * 8)) & UCHAR_MAX)) {
			status = SMW_STATUS_PUBLIC_EXPONENT_NOT_SUPPORTED;
			SMW_DBG_PRINTF(DEBUG,
				       "Unsupported RSA public exponent.\n");
			break;
		}
	}

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && hex_pub_data)
		SMW_UTILS_FREE(hex_pub_data);

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
	case OPERATION_ID_IMPORT_KEY:
		*status = import_key(hdl, args);
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = export_key(ele_ctx, args);
		break;
	case OPERATION_ID_DELETE_KEY:
		*status = delete_key(ele_ctx, args);
		break;
	case OPERATION_ID_GET_KEY_LENGTHS:
		*status = get_key_lengths(hdl, args);
		break;
	case OPERATION_ID_GET_KEY_ATTRIBUTES:
		*status = ele_get_key_attributes(hdl, args);
		break;
	case OPERATION_ID_COMMIT_KEY_STORAGE:
		*status = commit_key_storage(hdl);
		break;
	case OPERATION_ID_IS_OBJECT_PRESENT:
		return key_is_present(hdl, args, status);
	default:
		return false;
	}

	return true;
}
