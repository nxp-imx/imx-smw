// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
 */

#include "smw_config.h"
#include "smw_status.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "keymgr_derive.h"
#include "name.h"
#include "list.h"

#include "common.h"
#include "tag.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */
#define SMW_CONFIG_KEY_TYPE_ID_OFFSET                                          \
	(SMW_KEY_TYPE_NAME_SECP_R1 - SMW_CONFIG_KEY_TYPE_ID_SECP_R1)

#define SMW_CONFIG_KDF_ID_OFFSET (SMW_KDF_NAME_HKDF - SMW_CONFIG_KDF_ID_HKDF)

static const char *const key_type_strings[] = {
	[SMW_CONFIG_KEY_TYPE_ID_SECP_R1] = "SECP_R1",
	[SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_R1] = "BRAINPOOL_R1",
	[SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_T1] = "BRAINPOOL_T1",
	[SMW_CONFIG_KEY_TYPE_ID_ED25519] = "ED25519",
	[SMW_CONFIG_KEY_TYPE_ID_X25519] = "X25519",
	[SMW_CONFIG_KEY_TYPE_ID_AES] = "AES",
	[SMW_CONFIG_KEY_TYPE_ID_DES] = "DES",
	[SMW_CONFIG_KEY_TYPE_ID_DES3] = "DES3",
	[SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP] = "DSA_SM2_FP",
	[SMW_CONFIG_KEY_TYPE_ID_SM4] = "SM4",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC] = "HMAC",
	[SMW_CONFIG_KEY_TYPE_ID_RSA] = "RSA",
	[SMW_CONFIG_KEY_TYPE_ID_DH] = "DH",
	[SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER] = "TLS_MASTER",
	[SMW_CONFIG_KEY_TYPE_ID_RAW] = "RAW",
	[SMW_CONFIG_KEY_TYPE_ID_DERIVE] = "DERIVE"
};

static const char *const kdf_strings[] = {
	[SMW_CONFIG_KDF_ID_HKDF] = "HKDF",
	[SMW_CONFIG_KDF_ID_HKDF_EXTRACT] = "HKDF_EXTRACT",
	[SMW_CONFIG_KDF_ID_HKDF_EXPAND] = "HKDF_EXPAND",
	[SMW_CONFIG_KDF_ID_TLS12_KEY_EXCHANGE] = "TLS12_KEY_EXCHANGE",
	[SMW_CONFIG_KDF_ID_ECDH] = "ECDH",
	[SMW_CONFIG_KDF_ID_TLS12_OP_KEY_EXCHANGE] = "TLS12_OP_KEY_EXCHANGE",
	[SMW_CONFIG_KDF_ID_TLS13_KEY_EXCHANGE] = "TLS13_KEY_EXCHANGE",
	[SMW_CONFIG_KDF_ID_OEM_MASTER_KEY] = "OEM_MASTER_KEY"
};

static unsigned int derive_algo_attrs[] = {
	[SMW_CONFIG_KDF_ID_HKDF] = SMW_ATTR_ALGO_HKDF,
	[SMW_CONFIG_KDF_ID_HKDF_EXTRACT] = SMW_ATTR_ALGO_HKDF_EXTRACT,
	[SMW_CONFIG_KDF_ID_HKDF_EXPAND] = SMW_ATTR_ALGO_HKDF_EXPAND,
	[SMW_CONFIG_KDF_ID_TLS12_KEY_EXCHANGE] = SMW_ATTR_ALGO_TLS_1_2,
	[SMW_CONFIG_KDF_ID_ECDH] = SMW_ATTR_ALGO_ECDH,
	[SMW_CONFIG_KDF_ID_TLS12_OP_KEY_EXCHANGE] = SMW_ATTR_ALGO_TLS_1_2,
	[SMW_CONFIG_KDF_ID_TLS13_KEY_EXCHANGE] = SMW_ATTR_ALGO_TLS_1_3,
	[SMW_CONFIG_KDF_ID_NB] = 0,
};

static int read_key_type_strings(char **start, char *end, unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, key_type_strings,
					SMW_CONFIG_KEY_TYPE_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_KEY_TYPE_NAME;

	return status;
}

static int get_key_type_id(const char *type_string,
			   enum smw_config_key_type_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(type_string);

	status = smw_utils_get_string_index(type_string, key_type_strings,
					    SMW_CONFIG_KEY_TYPE_ID_NB, id);

	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_KEY_TYPE_NAME;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int read_key_size_range(char **start, char *end, const char *type_string,
			       unsigned long *size_range_bitmap,
			       struct op_key *key)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	enum smw_config_key_type_id id = SMW_CONFIG_KEY_TYPE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(size_range_bitmap);

	status = get_key_type_id(type_string, &id);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Key size range cannot be defined twice */
	if (check_id(id, *size_range_bitmap)) {
		status = SMW_STATUS_RANGE_DUPLICATE;
		goto end;
	}

	/* Key type must be listed before size range is defined */
	if (!check_id(id, key->type_bitmap)) {
		status = SMW_STATUS_ALGO_NOT_CONFIGURED;
		goto end;
	}

	status = read_range(&cur, end, &key->size_range[id]);
	if (status != SMW_STATUS_OK)
		goto end;

	set_bit(size_range_bitmap, sizeof(*size_range_bitmap) << 3, id);

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static bool read_key_op_strings(char **start, char *end,
				enum operation_id op_id, unsigned long *bitmap,
				int *status)
{
	bool read_key_op_type_value = false;
	const char *const *op_names = NULL;
	unsigned int nb_op_names = 0;

	switch (op_id) {
	case OPERATION_ID_DERIVE_KEY:
		op_names = kdf_strings;
		nb_op_names = SMW_CONFIG_KDF_ID_NB;
		read_key_op_type_value = true;
		break;

	default:
		return read_key_op_type_value;
	}

	*status = smw_config_read_strings(start, end, bitmap, op_names,
					  nb_op_names);
	if (*status == SMW_STATUS_UNKNOWN_NAME)
		*status = SMW_STATUS_UNKNOWN_KDF_NAME;

	return read_key_op_type_value;
}

bool read_key(char *tag, size_t length, char **start, char *end,
	      unsigned long *key_size_range_bitmap, struct op_key *key,
	      int *status)
{
	bool match = false;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!SMW_UTILS_STRNCMP(tag, key_type_values, length)) {
		match = true;
		*status = read_key_type_strings(&cur, end, &key->type_bitmap);
	} else if (get_tag_prefix(tag, length, _size_range)) {
		match = true;
		*status = read_key_size_range(&cur, end, tag,
					      key_size_range_bitmap, key);
	}

	if (match && *status == SMW_STATUS_OK)
		*start = cur;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %s\n", __func__,
		       match ? "true" : "false");
	return match;
}

static int read_params(char **start, char *end, enum operation_id operation_id,
		       void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_STRING_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct key_operation_params *p = NULL;
	unsigned long key_size_range_bitmap = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = SMW_UTILS_CALLOC(1, sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	init_key_params(&p->key);

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_string(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, op_type_values, length)) {
			if (read_key_op_strings(&cur, end, operation_id,
						&p->op_bitmap, &status)) {
				if (status != SMW_STATUS_OK)
					goto end;
			} else {
				status = skip_param(&cur, end);
				if (status != SMW_STATUS_OK)
					goto end;
			}
		} else if (read_key(buffer, length, &cur, end,
				    &key_size_range_bitmap, &p->key, &status)) {
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	if (!p->op_bitmap)
		p->op_bitmap = SMW_ALL_ONES;

	if (!p->key.type_bitmap)
		p->key.type_bitmap = SMW_ALL_ONES;

	*params = p;

	*start = cur;

end:
	if (p && status != SMW_STATUS_OK)
		SMW_UTILS_FREE(p);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_GENERATE_KEY, params);
}

static int derive_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_DERIVE_KEY, params);
}

static int derive_key_usable(unsigned int *ref,
			     enum smw_config_key_type_id key_type_id,
			     struct smw_key_attributes *attributes)
{
	int status = SMW_STATUS_OK;

	struct key_operation_params params = { 0 };
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	size_t idx = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_operation_params(OPERATION_ID_DERIVE_KEY, ref, &params);
	if (status != SMW_STATUS_OK)
		goto end;

	algo = SMW_ATTR_GET_ALGO(attributes->permitted_algo);

	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	if (!check_id(key_type_id, params.key.type_bitmap))
		goto end;

	for (; idx < ARRAY_SIZE(derive_algo_attrs); idx++) {
		if (algo == derive_algo_attrs[idx] &&
		    check_id(idx, params.op_bitmap)) {
			status = SMW_STATUS_OK;
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int import_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_IMPORT_KEY, params);
}

static int export_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_EXPORT_KEY, params);
}

static int delete_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_DELETE_KEY, params);
}

static void merge_params(void *caps, void *params)
{
	struct key_operation_params *key_operation_caps = caps;
	struct key_operation_params *key_operation_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_operation_caps->op_bitmap |= key_operation_params->op_bitmap;
	merge_key_params(&key_operation_caps->key, &key_operation_params->key);
}

__weak void print_key_operation_params(void *params)
{
	(void)params;
}

static int check_key_descriptor(struct smw_keymgr_descriptor *key_descriptor,
				struct key_operation_params *params)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_key(&key_descriptor->identifier, &params->key))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak int cipher_key_usable(unsigned int *ref,
			     enum smw_config_key_type_id key_type_id,
			     struct smw_key_attributes *attributes)
{
	(void)ref;
	(void)key_type_id;
	(void)attributes;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int sign_key_usable(unsigned int *ref,
			   enum smw_config_key_type_id key_type_id,
			   struct smw_key_attributes *attributes)
{
	(void)ref;
	(void)key_type_id;
	(void)attributes;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int aead_key_usable(unsigned int *ref,
			   enum smw_config_key_type_id key_type_id,
			   struct smw_key_attributes *attributes)
{
	(void)ref;
	(void)key_type_id;
	(void)attributes;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int mac_key_usable(unsigned int *ref,
			  enum smw_config_key_type_id key_type_id,
			  struct smw_key_attributes *attributes)
{
	(void)ref;
	(void)key_type_id;
	(void)attributes;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int asymm_encrypt_key_usable(unsigned int *ref,
				    enum smw_config_key_type_id key_type_id,
				    struct smw_key_attributes *attributes)
{
	(void)ref;
	(void)key_type_id;
	(void)attributes;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

static int check_key_attributes(struct smw_keymgr_descriptor *key_desc,
				struct smw_key_attributes *attributes,
				unsigned int ref)
{
	int status = SMW_STATUS_OK;

	smw_attr_algo_t class = SMW_ATTR_CLASS_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!attributes) {
		status = SMW_STATUS_OK;
		goto end;
	}

	if (ref >= SUBSYSTEM_ID_NB) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	class = SMW_ATTR_GET_CLASS(attributes->permitted_algo);

	/*
	 * There may be multiple subsystems which support an operation, but not
	 * necessarily with the same key types/modes. For example, TEE could have:
	 * [SECURITY_OPERATION]
	 *   AEAD;
	 *     KEY_TYPE_VALUES=AES;
	 *     MODE_VALUES=CCM;
	 * While ELE could have:
	 * [SECURITY_OPERATION]
	 *   AEAD;
	 *     KEY_TYPE_VALUES=AES;
	 *     MODE_VALUES=CCM:CHACHA20_POLY1305;
	 *
	 * In this case, both ELE and TEE support keys for the CCM mode. But
	 * only ELE supports keys for the CHACHA20_POLY1305 mode. So, during key
	 * generation, search for the configured operations for the first match
	 * for both the key type and algorithm.
	 */

	switch (class) {
	case SMW_ATTR_CLASS_SYMMETRIC_ENCRYPTION:
		status = cipher_key_usable(&ref, key_desc->identifier.type_id,
					   attributes);
		break;

	case SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE:
		status = sign_key_usable(&ref, key_desc->identifier.type_id,
					 attributes);
		break;

	case SMW_ATTR_CLASS_AEAD:
		status = aead_key_usable(&ref, key_desc->identifier.type_id,
					 attributes);
		break;

	case SMW_ATTR_CLASS_MAC:
		status = mac_key_usable(&ref, key_desc->identifier.type_id,
					attributes);
		break;

	case SMW_ATTR_CLASS_KEY_DERIVATION:
		status = derive_key_usable(&ref, key_desc->identifier.type_id,
					   attributes);
		break;

	case SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION:
		status = asymm_encrypt_key_usable(&ref,
						  key_desc->identifier.type_id,
						  attributes);
		break;

	default:
		status = SMW_STATUS_OK;
		break;
		;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_generate_key_args *key_args =
		(struct smw_keymgr_generate_key_args *)args;
	unsigned int ref = smw_utils_list_get_ref(node);
	struct key_operation_params *op_params = smw_utils_list_get_data(node);

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_key_descriptor(&key_args->key_descriptor, op_params);
	if (status == SMW_STATUS_OK)
		status = check_key_attributes(&key_args->key_descriptor,
					      key_args->key_attributes, ref);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int derive_key_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args *derive_args = args;
	struct key_operation_params *op_params = smw_utils_list_get_data(node);

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_key_descriptor(&derive_args->key_base, op_params);

	/*
	 * Check if the Key Derivation Function ID specified is
	 * supported by the subsystem.
	 */
	if (status == SMW_STATUS_OK &&
	    derive_args->kdf_id != SMW_CONFIG_KDF_ID_INVALID) {
		if (!check_id(derive_args->kdf_id, op_params->op_bitmap))
			status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int import_key_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_import_key_args *key_args =
		(struct smw_keymgr_import_key_args *)args;
	unsigned int ref = smw_utils_list_get_ref(node);
	struct key_operation_params *op_params = smw_utils_list_get_data(node);

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_key_descriptor(&key_args->key_descriptor, op_params);
	if (status == SMW_STATUS_OK)
		status = check_key_attributes(&key_args->key_descriptor,
					      key_args->key_attributes, ref);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int export_key_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor =
		&((struct smw_keymgr_export_key_args *)args)->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_key_descriptor(key_descriptor,
				      smw_utils_list_get_data(node));

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor =
		&((struct smw_keymgr_delete_key_args *)args)->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_key_descriptor(key_descriptor,
				      smw_utils_list_get_data(node));

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define DEFINE_KEYMGR_OPERATION_FUNC(operation)                                \
	struct operation_func operation##_func = {                             \
		.read = operation##_read_params,                               \
		.merge = merge_params,                                         \
		.print = print_key_operation_params,                           \
		.check_subsystem_caps = operation##_check_subsystem_caps,      \
	};                                                                     \
	struct operation_func *smw_##operation##_get_func(void)                \
	{                                                                      \
		return &operation##_func;                                      \
	}

DEFINE_KEYMGR_OPERATION_FUNC(generate_key);
DEFINE_KEYMGR_OPERATION_FUNC(derive_key);
DEFINE_KEYMGR_OPERATION_FUNC(import_key);
DEFINE_KEYMGR_OPERATION_FUNC(export_key);
DEFINE_KEYMGR_OPERATION_FUNC(delete_key);

int smw_config_get_key_type_id(smw_key_type_t name,
			       enum smw_config_key_type_id *id)
{
	int status = SMW_STATUS_UNKNOWN_KEY_TYPE_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_KEY_TYPE_NAME_NONE) {
		*id = SMW_CONFIG_KEY_TYPE_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_KEY_TYPE_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_KEY_TYPE_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

smw_key_type_t smw_config_get_key_type_name(enum smw_config_key_type_id id)
{
	smw_key_type_t name = SMW_KEY_TYPE_NAME_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (id < SMW_CONFIG_KEY_TYPE_ID_NB &&
	    id != SMW_CONFIG_KEY_TYPE_ID_INVALID)
		(void)ADD_OVERFLOW(id, SMW_CONFIG_KEY_TYPE_ID_OFFSET,
				   (int *)&name);

	return name;
}

int smw_config_get_kdf_id(smw_kdf_t name, enum smw_config_kdf_id *id)
{
	int status = SMW_STATUS_UNKNOWN_KDF_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_KDF_NAME_NONE) {
		*id = SMW_CONFIG_KDF_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_KDF_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_KDF_ID_OFFSET, (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

__export enum smw_status_code
smw_config_check_generate_key(smw_subsystem_t subsystem,
			      struct smw_key_info *info)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_key_type_id key_type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;
	struct key_operation_params params = { 0 };
	struct range *key_size_range = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info || info->key_type_name == SMW_KEY_TYPE_NAME_NONE)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(info->key_type_name, &key_type_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params_lock(OPERATION_ID_GENERATE_KEY, id,
					   &params);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(key_type_id, params.key.type_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	key_size_range = &params.key.size_range[key_type_id];
	if (info->security_size) {
		if (!check_size(info->security_size, key_size_range))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	} else {
		info->security_size_min = key_size_range->min;
		info->security_size_max = key_size_range->max;
	}

	return SMW_STATUS_OK;
}

__export enum smw_status_code
smw_config_check_derive_key(smw_subsystem_t subsystem, smw_kdf_t kdf)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;

	enum smw_config_kdf_id kdf_id = SMW_CONFIG_KDF_ID_INVALID;

	struct key_operation_params op_params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (kdf == SMW_KDF_NAME_NONE)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_kdf_id(kdf, &kdf_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params_lock(OPERATION_ID_DERIVE_KEY, id,
					   &op_params);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(kdf_id, op_params.op_bitmap))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
