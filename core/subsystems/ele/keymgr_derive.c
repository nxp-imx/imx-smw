// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022, 2024 NXP
 */
#include "smw_osal.h"
#include "smw_status.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "keymgr_derive_hkdf.h"

#include "common.h"

#define HKDF_FULL_ALGO(_id)                                                    \
	{                                                                      \
		.hash_algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                 \
		.key_derive_algo = HSM_KEY_DERIVATION_HKDF_##_id,              \
		.hkdf_step = HKDF_STEP_FULL                                    \
	}

#define HKDF_ALGO(_id, _step)                                                  \
	{                                                                      \
		.hash_algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                 \
		.key_derive_algo = HSM_KEY_DERIVATION_HKDF_##_step##_##_id,    \
		.hkdf_step = HKDF_STEP_##_step                                 \
	}

#define KEY_DEF(_key_type_id, _key_type)                                       \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.key_type = HSM_KEY_TYPE_##_key_type,                          \
	}

/**
 * struct key_derive_algo - ELE Key derivation algorithm
 * @hash_algo_id: SMW algo ID
 * @key_derive_algo: ELE key derivation algo ID
 * @hkdf_step: HKDF Step
 */
static const struct key_derive_algo {
	enum smw_config_hash_algo_id hash_algo_id;
	hsm_op_key_derivation_algo_t key_derive_algo;
	enum hkdf_step hkdf_step;
} key_derive_algo_list[] = {
	HKDF_FULL_ALGO(SHA256),	    HKDF_FULL_ALGO(SHA384),
	HKDF_ALGO(SHA256, EXTRACT), HKDF_ALGO(SHA384, EXTRACT),
	HKDF_ALGO(SHA256, EXPAND),  HKDF_ALGO(SHA384, EXPAND),
};

static int get_key_derive_algo(struct smw_keymgr_hkdf_args *hkdf_args,
			       hsm_op_key_derivation_algo_t *key_derive_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_derive_algo_list);

	enum smw_config_hash_algo_id hash_algo_id = hkdf_args->prf_id;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(hkdf_args);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (key_derive_algo_list[i].hkdf_step == step) {
			if (key_derive_algo_list[i].hash_algo_id ==
			    hash_algo_id) {
				*key_derive_algo =
					key_derive_algo_list[i].key_derive_algo;
				status = SMW_STATUS_OK;
				break;
			}
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * struct derive_key_type - ELE Key definition
 * @key_type_id: SMW key type ID
 * @key_type: ELE derive key type
 */
static const struct derive_key_type {
	enum smw_config_key_type_id key_type_id;
	uint16_t key_type;
} derive_key_type_list[] = { KEY_DEF(AES, AES), KEY_DEF(HMAC, HMAC) };

static int get_derived_key_type(enum smw_config_key_type_id key_type_id,
				uint16_t *key_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(derive_key_type_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (derive_key_type_list[i].key_type_id == key_type_id) {
			*key_type = derive_key_type_list[i].key_type;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_base_key_buffer() - Get the base key buffer in HEX format.
 * @key_desc: Pointer to internal Key descriptor structure
 * @hex_key: Pointer to the HEX buffer to update
 * @hex_key_len: @hex_key length to update
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - One of the parameters is invalid.
 * Error code from smw_keymgr_set_hex_key_buffer()
 */
static int get_base_key_buffer(struct smw_keymgr_descriptor *key_desc,
			       unsigned char **hex_key,
			       unsigned int *hex_key_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *key = NULL;
	unsigned int key_len = 0;

	key = smw_keymgr_get_public_data(key_desc);
	key_len = smw_keymgr_get_public_length(key_desc);
	if (!key || !key_len)
		goto exit;

	status = smw_keymgr_set_hex_key_buffer(key_desc->format_id, key,
					       key_len, hex_key, hex_key_len);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_derived_key_buffer() - Set the derived key buffer in HEX format
 * @key_ex_args: Pointer to ELE key exchange argument structure
 * @key_desc: Pointer to internal derived Key descriptor structure
 * @hex_key: Pointer to the HEX buffer to update
 * @hex_key_len: @hex_key length to update
 *
 * Set the derived key buffer in HEX format in key exchange argument if the
 * derived key is to be exported.
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - One of the parameters is invalid.
 * Error code from smw_keymgr_set_hex_key_buffer()
 */
static int set_derived_key_buffer(op_key_exchange_args_t *key_ex_args,
				  struct smw_keymgr_derived_key_desc *key_desc,
				  unsigned char **hex_key,
				  unsigned int *hex_key_len)
{
	int status = SMW_STATUS_OK;

	unsigned char *key = NULL;
	unsigned int key_len = 0;

	if (!(key_ex_args->flags & HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT))
		return status;

	key = smw_keymgr_get_shared_secret_buffer(key_desc);
	key_len = smw_keymgr_get_shared_secret_len(key_desc);
	if (!key || !key_len) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	status = smw_keymgr_set_hex_key_buffer(key_desc->format_id, key,
					       key_len, hex_key, hex_key_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_ex_args->output = *hex_key;
	if (key_ex_args->output)
		key_ex_args->output_sz = *hex_key_len;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_store_id(uint32_t *keystore_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct se_info info = { 0 };

	if (smw_utils_get_subsystem_info(SMW_SUBSYSTEM_NAME_ELE, &info))
		goto end;

	*keystore_id = info.storage_id;
	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_lifetime(smw_attr_attributes_t attributes,
			    hsm_key_lifetime_t *key_lifetime)
{
	int status = SMW_STATUS_OK;

	smw_attr_attributes_t persistence =
		SMW_ATTR_GET_PERSISTENCE(attributes);

	switch (persistence) {
	case SMW_ATTR_PERSISTENCE_PERSISTENT:
		*key_lifetime = HSM_SE_KEY_STORAGE_PERSISTENT;
		break;

	case SMW_ATTR_PERSISTENCE_PERMANENT:
		*key_lifetime = HSM_SE_KEY_STORAGE_PERS_PERM;
		break;

	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		*key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		break;
	}

	return status;
}

static void set_hkdf_op_flags(struct smw_keymgr_derive_key_args *args,
			      hsm_op_key_exchange_flags_t *flags)
{
	*flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;

	if (smw_keymgr_get_shared_secret_buffer(&args->key_derived) &&
	    smw_keymgr_get_shared_secret_len(&args->key_derived))
		*flags |= HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
}

/**
 * set_derived_key_attr() - Set the derived key attributes
 * @args: Pointer to internal derived Key arguments structure
 * @hkdf_op_payload: Pointer to Key Exchange input content argument structure
 * @actual_permitted_algo: Pointer to SMW permitted algorithm
 * @actual_usage_flags: Pointer to SMW usage flags
 *
 * This function sets the derived key type, permitted algo, key usage and key
 * lifetime of derived key and returns actual permitted algo and usage flag set.
 *
 * Return:
 * SMW_STATUS_OK                      - Success.
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Key type not supported.
 */
static int set_derived_key_attr(struct smw_keymgr_derive_key_args *args,
				struct hkdf_ele_op_payload *hkdf_op_payload,
				smw_attr_algo_t *actual_permitted_algo,
				smw_attr_usage_t *actual_usage_flags)
{
	int status = SMW_STATUS_INVALID_PARAM;

	hsm_permitted_algo_t ele_permitted_algo = 0;

	struct smw_key_attributes *key_attrs = args->key_attributes;
	smw_attr_attributes_t attr = args->key_derived.identifier.attributes;

	if (!key_attrs)
		goto end;

	status = get_derived_key_type(args->key_derived.identifier.type_id,
				      &hkdf_op_payload->key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	ele_set_key_policy(&hkdf_op_payload->key_permit_algo,
			   &hkdf_op_payload->key_usage,
			   key_attrs->permitted_algo, key_attrs->usage_flags);

	if (SET_OVERFLOW(hkdf_op_payload->key_permit_algo,
			 ele_permitted_algo)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	ele_get_key_policy(actual_permitted_algo, actual_usage_flags,
			   ele_permitted_algo, hkdf_op_payload->key_usage);

	status = get_key_lifetime(attr, &hkdf_op_payload->key_lifetime);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_prk_attributes() - Set the PRK attributes
 * @key_attr: Pointer to SMW attributes
 * @hkdf_op_payload: Pointer to Key Exchange input content argument structure
 *
 * This function sets the key lifetime and lifecycle (current) of PRK.
 *
 * Return:
 * SMW_STATUS_OK                      - Success.
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid.
 */
static int set_prk_attributes(smw_attr_attributes_t *key_attr,
			      struct hkdf_ele_op_payload *hkdf_op_payload)
{
	int status = SMW_STATUS_OK;

	status = get_key_lifetime(*key_attr, &hkdf_op_payload->key_lifetime);

	hkdf_op_payload->key_lifecycle = 0;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * set_derived_key_params() - Set the derived key params
 * @key_ex_args: Pointer to ELE key exchange argument structure
 * @args: Pointer to internal derived Key arguments structure
 * @hkdf_op_payload: Pointer to Key Exchange input content argument structure
 * @actual_permitted_algo: Pointer to SMW permitted algorithm.
 * @actual_usage_flags: Pointer to SMW usage flags
 * @step: HKDF Step
 *
 * This function sets derived key attributes if the user has requested to store
 * the key (instead of exporting the derived key).
 *
 * - HKDF Full/Extract step: Key type, lifetime, usage attributes, permitted
 *   algorithms and lifecycle of derived key are set.
 *
 * - HKDF Extract step: Key lifetime and key lifecycle of derived key (PRK) are
 *   set.
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Key type not supported
 */
static int set_derived_key_params(op_key_exchange_args_t *key_ex_args,
				  struct smw_keymgr_derive_key_args *args,
				  smw_attr_algo_t *actual_permitted_algo,
				  smw_attr_usage_t *actual_usage_flags,
				  enum hkdf_step step)
{
	int status = SMW_STATUS_OK;
	struct hkdf_ele_op_payload *hkdf_op_payload = NULL;
	smw_attr_attributes_t *key_attr = NULL;

	if (!(key_ex_args->flags & HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT)) {
		hkdf_op_payload =
			(struct hkdf_ele_op_payload *)key_ex_args->in_content;

		if (step == HKDF_STEP_EXTRACT) {
			key_attr = &args->key_derived.identifier.attributes;
			status = set_prk_attributes(key_attr, hkdf_op_payload);
		} else {
			status = set_derived_key_attr(args, hkdf_op_payload,
						      actual_permitted_algo,
						      actual_usage_flags);
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * set_derived_key_id_length() - Set the derived key parameters
 * @step: HKDF Step
 * @status: Status of key derivation operation
 * @args: Pointer to ELE key exchange arguments structure
 * @desc: Pointer to internal derived Key descriptor structure
 *
 * If derived key to be exported and the key derivation has returned
 * SMW_STATUS_OUTPUT_TOO_SHORT, update the derived key buffer length.
 *
 * If the derived key is stored in the ELE storage, update the derived key
 * identifier structure members (key ID, subsystem ID, privacy ID).
 *
 * If the step is HKDF EXTRACT, update the PRK ID in the public key descriptor
 * structure.
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 */
static int set_derived_key_id_length(enum hkdf_step step, int status,
				     op_key_exchange_args_t *args,
				     struct smw_keymgr_derived_key_desc *desc)
{
	struct smw_keymgr_identifier *key_id = NULL;
	bool return_output_flag = false;
	int result = status;

	if (args->flags & HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT)
		return_output_flag = true;

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		if (return_output_flag)
			smw_keymgr_set_shared_secret_len(desc,
							 args->exp_output_sz);
	} else if (status == SMW_STATUS_OK) {
		if (return_output_flag)
			return result;

		key_id = &desc->identifier;
		key_id->subsystem_id = SUBSYSTEM_ID_ELE;
		key_id->id = args->out_derived_key_id;

		if (step == HKDF_STEP_EXTRACT)
			smw_keymgr_set_shared_secret_id(desc, key_id->id);
		else
			result = smw_keymgr_get_privacy_id(key_id->type_id,
							   &key_id->privacy_id);
	}

	return result;
}

/**
 * hkdf() - Perform HKDF Full/Extract/Expand step.
 * @args: Pointer Key derivation arguments structure
 * @key_mgt_hdl: Pointer to key management service flow handle
 *
 * Return:
 * SMW_STATUS_OK                - Success.
 * SMW_STATUS_INVALID_PARAM     - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE     - Memory allocation failure.
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Output buffer is too short
 * SMW_STATUS_OPERATION_FAILURE - Operation failed
 * SMW_STATUS_SUBSYSTEM_FAILURE - Subsytem failed.
 */
static int hkdf(struct smw_keymgr_derive_key_args *args, hsm_hdl_t *key_mgt_hdl)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	struct smw_keymgr_identifier *key_id_base = NULL;
	struct smw_keymgr_identifier *key_id_derived = NULL;
	struct smw_key_attributes *key_attrs = args->key_attributes;

	unsigned char *hex_key_base = NULL;
	unsigned int hex_key_base_len = 0;
	unsigned char *hex_key_derived = NULL;
	unsigned int hex_key_derived_len = 0;
	unsigned char *buffer = NULL;
	uint8_t *arg_buffer = NULL;
	unsigned int buffer_size = 0;

	enum hkdf_step step = HKDF_STEP_INVALID;

	smw_attr_algo_t actual_perm_algo = 0;
	smw_attr_usage_t actual_usage = SMW_ATTR_USAGE_NONE;

	hsm_err_t err = HSM_NO_ERROR;
	struct hkdf_ele_op_payload hkdf_op_payload = { 0 };
	op_key_exchange_args_t key_ex_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	hkdf_args = args->kdf_args;
	key_id_base = &args->key_base.identifier;
	key_id_derived = &args->key_derived.identifier;

	if (!hkdf_args || !key_id_base || !key_id_derived)
		goto exit;

	step = smw_keymgr_get_hkdf_step(hkdf_args);

	if (key_id_base->id != INVALID_KEY_ID) {
		hkdf_op_payload.key_id = key_id_base->id;

		if (step == HKDF_STEP_EXTRACT || step == HKDF_STEP_FULL) {
			key_ex_args.in_pub_buffer =
				smw_keymgr_get_peer_pub_buffer(hkdf_args);
			key_ex_args.in_pub_buffer_sz =
				smw_keymgr_get_peer_pub_buffer_len(hkdf_args);
		}
	} else if (key_id_base->type_id == SMW_CONFIG_KEY_TYPE_ID_RAW) {
		status = get_base_key_buffer(&args->key_base, &hex_key_base,
					     &hex_key_base_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		if (step == HKDF_STEP_EXPAND) {
			hkdf_op_payload.buffer_len = hex_key_base_len;
			buffer = hex_key_base;
		} else {
			key_ex_args.in_pub_buffer = hex_key_base;
			key_ex_args.in_pub_buffer_sz = hex_key_base_len;
		}
	}

	hkdf_op_payload.ver = 1;

	status = get_key_store_id(&hkdf_op_payload.keystore_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = get_key_derive_algo(hkdf_args, &hkdf_op_payload.hkdf_algo);
	if (status != SMW_STATUS_OK)
		goto exit;

	set_hkdf_op_flags(args, &key_ex_args.flags);

	status = set_derived_key_buffer(&key_ex_args, &args->key_derived,
					&hex_key_derived, &hex_key_derived_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (step == HKDF_STEP_FULL || step == HKDF_STEP_EXPAND) {
		/*
		 * Currently, user can either store the derived key or export the
		 * derived key buffer, but can't do both.
		 */
		if (smw_keymgr_is_store_key_set(args) && hex_key_derived &&
		    hex_key_derived_len) {
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
			goto exit;
		}

		if (!smw_keymgr_is_store_key_set(args) &&
		    (!hex_key_derived || !hex_key_derived_len)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	/*
	 * For HKDF FULL/EXPAND step, if the derived key security size is not
	 * defined by the user and user has set the derived key buffer to export the
	 * derived key, calculate the derived key security size based on derived
	 * key buffer length.
	 */
	if (step == HKDF_STEP_FULL || step == HKDF_STEP_EXPAND) {
		if (key_id_derived->security_size) {
			if (SET_OVERFLOW(key_id_derived->security_size,
					 hkdf_op_payload.key_size)) {
				status = SMW_STATUS_INVALID_PARAM;
				goto exit;
			}
		} else if (hex_key_derived && hex_key_derived_len) {
			if (MUL_OVERFLOW(hex_key_derived_len, 8,
					 &hkdf_op_payload.key_size)) {
				status = SMW_STATUS_INVALID_PARAM;
				goto exit;
			}
		}

		key_ex_args.user_fixed_info_sz =
			smw_keymgr_get_info_len(hkdf_args);
		key_ex_args.user_fixed_info = smw_keymgr_get_info(hkdf_args);
	}

	if (step == HKDF_STEP_EXTRACT || step == HKDF_STEP_FULL) {
		buffer = smw_keymgr_get_salt(hkdf_args);
		hkdf_op_payload.buffer_len = smw_keymgr_get_salt_len(hkdf_args);
	}

	if (buffer && hkdf_op_payload.buffer_len) {
		if (ADD_OVERFLOW(sizeof(struct hkdf_ele_op_payload),
				 hkdf_op_payload.buffer_len, &buffer_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}

		arg_buffer = SMW_UTILS_CALLOC(1, buffer_size);
		if (!arg_buffer) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto exit;
		}

		SMW_UTILS_MEMCPY(arg_buffer, (void *)&hkdf_op_payload,
				 sizeof(hkdf_op_payload));
		SMW_UTILS_MEMCPY(arg_buffer + sizeof(hkdf_op_payload),
				 (void *)buffer, hkdf_op_payload.buffer_len);

		key_ex_args.in_content_sz = buffer_size;
		key_ex_args.in_content = arg_buffer;

	} else {
		key_ex_args.in_content_sz = sizeof(hkdf_op_payload);
		key_ex_args.in_content = (uint8_t *)(&hkdf_op_payload);
	}

	status = set_derived_key_params(&key_ex_args, args, &actual_perm_algo,
					&actual_usage, step);
	if (status != SMW_STATUS_OK)
		goto exit;

	SMW_DBG_PRINTF(VERBOSE,
		       " Call hsm_key_exchange()\n"
		       "  HKDF Full/Extract\n"
		       "  flags: 0x%04X\n"
		       "  in_pub_buffer_sz: %d\n"
		       "  user_fixed_info_sz: %d\n"
		       "  in_content_sz: %d\n"
		       "  in_content: %p\n"
		       "  op_payload params\n"
		       "    - ver: %d\n"
		       "    - keystore_id: %d\n"
		       "    - hkdf_algo: 0x%x\n"
		       "    - key_id: %u\n"
		       "    - key_type: 0x%04X\n"
		       "    - key_size: %d\n"
		       "    - key_lifetime: 0x%X\n"
		       "    - key_usage: 0x%04X\n"
		       "    - key_permit_algo: 0x%08X\n"
		       "    - key_lifecycle: 0x%X\n"
		       "    - derived_key_id: %d\n"
		       "    - PRK_len/salt_len: %d\n"
		       "  out_derived_key_id: %d\n"
		       "  expected_out_sz: %d\n"
		       "  output_sz: %d\n"
		       "  output: %p\n"
		       "  PRK/salt: %p\n",
		       key_ex_args.flags, key_ex_args.in_pub_buffer_sz,
		       key_ex_args.user_fixed_info_sz,
		       key_ex_args.in_content_sz, key_ex_args.in_content,
		       hkdf_op_payload.ver, hkdf_op_payload.keystore_id,
		       hkdf_op_payload.hkdf_algo, hkdf_op_payload.key_id,
		       hkdf_op_payload.key_type, hkdf_op_payload.key_size,
		       hkdf_op_payload.key_lifetime, hkdf_op_payload.key_usage,
		       hkdf_op_payload.key_permit_algo,
		       hkdf_op_payload.key_lifecycle,
		       hkdf_op_payload.derived_key_id,
		       hkdf_op_payload.buffer_len,
		       key_ex_args.out_derived_key_id,
		       key_ex_args.exp_output_sz, key_ex_args.output_sz,
		       key_ex_args.output, buffer);

	err = hsm_key_exchange(*key_mgt_hdl, &key_ex_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);

	status = ele_convert_err(err);

	status = set_derived_key_id_length(step, status, &key_ex_args,
					   &args->key_derived);

exit:

	if (arg_buffer)
		SMW_UTILS_FREE(arg_buffer);

	if (args->key_base.format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    hex_key_base)
		SMW_UTILS_FREE(hex_key_base);

	if (args->key_derived.format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    hex_key_derived)
		SMW_UTILS_FREE(hex_key_derived);

	if (step != HKDF_STEP_EXTRACT && key_attrs &&
	    (key_attrs->usage_flags != actual_usage ||
	     key_attrs->permitted_algo != actual_perm_algo)) {
		key_attrs->usage_flags = actual_usage;
		key_attrs->permitted_algo = actual_perm_algo;

		if (status == SMW_STATUS_OK)
			status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int derive_hkdf(struct hdl *hdl, struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_OK;

	hsm_hdl_t key_mgt_hdl = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = hkdf(args, &key_mgt_hdl);

	tmp_status = close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak int derive_tls12(struct hdl *hdl,
			struct smw_keymgr_derive_key_args *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

int ele_derive_key(struct hdl *hdl, struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(args);

	switch (args->kdf_id) {
	case SMW_CONFIG_KDF_ID_TLS12_KEY_EXCHANGE:
		status = derive_tls12(hdl, args);
		break;

	case SMW_CONFIG_KDF_ID_HKDF:
	case SMW_CONFIG_KDF_ID_HKDF_EXTRACT:
	case SMW_CONFIG_KDF_ID_HKDF_EXPAND:
		status = derive_hkdf(hdl, args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
