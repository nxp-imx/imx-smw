// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */
#include "smw_osal.h"
#include "smw_status.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"

#include "common.h"
#include "key_group.h"

#define HKDF_FULL_ALGO(_id)                                                    \
	{                                                                      \
		.hash_algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                 \
		.key_derive_algo = HSM_KEY_DERIVATION_HKDF_##_id,              \
		.hkdf_step = SMW_HKDF_STEP_FULL                                \
	}

#define HKDF_ALGO(_id, _step)                                                  \
	{                                                                      \
		.hash_algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                 \
		.key_derive_algo = HSM_KEY_DERIVATION_HKDF_##_step##_##_id,    \
		.hkdf_step = SMW_HKDF_STEP_##_step                             \
	}

#define KEY_DEF(_key_type_id, _key_type)                                       \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.key_type = HSM_KEY_TYPE_##_key_type,                          \
	}

/**
 * struct key_derive_algo - ELE key derivation algorithm
 * @hash_algo_id: SMW algo ID
 * @key_derive_algo: ELE key derivation algo ID
 * @hkdf_step: HKDF Step
 */
static const struct key_derive_algo {
	enum smw_config_hash_algo_id hash_algo_id;
	hsm_op_key_derivation_algo_t key_derive_algo;
	enum smw_hkdf_step hkdf_step;
} key_derive_algo_list[] = { HKDF_FULL_ALGO(SHA256), HKDF_ALGO(SHA256, EXTRACT),
			     HKDF_ALGO(SHA256, EXPAND) };

static int get_key_derive_algo(struct smw_keymgr_hkdf_args *hkdf_args,
			       enum smw_hkdf_step step,
			       hsm_op_key_derivation_algo_t *key_derive_algo)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum smw_config_hash_algo_id hash_algo_id = 0;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_derive_algo_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!hkdf_args || !key_derive_algo)
		goto exit;

	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	hash_algo_id = hkdf_args->prf_id;

	for (; i < size; i++) {
		if (key_derive_algo_list[i].hkdf_step == step &&
		    key_derive_algo_list[i].hash_algo_id == hash_algo_id) {
			*key_derive_algo =
				key_derive_algo_list[i].key_derive_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * struct derive_key_type - ELE key definition
 * @key_type_id: SMW key type ID
 * @key_type: ELE derive key type
 */
static const struct derive_key_type {
	enum smw_config_key_type_id key_type_id;
	uint16_t key_type;
} derive_key_type_list[] = { KEY_DEF(AES, AES), KEY_DEF(HMAC, HMAC),
			     KEY_DEF(DERIVE, DERIVE) };

static int get_derived_key_type(enum smw_config_key_type_id key_type_id,
				uint16_t *key_type)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(derive_key_type_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_type)
		goto exit;

	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	for (; i < size; i++) {
		if (derive_key_type_list[i].key_type_id == key_type_id) {
			*key_type = derive_key_type_list[i].key_type;
			status = SMW_STATUS_OK;
			break;
		}
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_lifetime(smw_attr_attributes_t attributes,
			    hsm_key_lifetime_t *key_lifetime)
{
	int status = SMW_STATUS_INVALID_PARAM;
	smw_attr_attributes_t persistence =
		SMW_ATTR_GET_PERSISTENCE(attributes);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_lifetime)
		goto exit;

	switch (persistence) {
	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		*key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		status = SMW_STATUS_OK;
		break;

	default:
		/*
		 * ELE HKDF key derivation only supports volatile (transient)
		 * derived keys.
		 */
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_key_store_args() - Set the key store arguments for opaque operation
 * @ele_ctx: Pointer to ELE subsystem context
 * @args: Pointer to internal derived key arguments structure
 * @key_store_args: Pointer to key store arguments structure
 * @key_group: Pointer to the derived key group (in/out)
 * @actual_permitted_algo: Pointer to SMW permitted algorithm
 * @actual_usage_flags: Pointer to SMW usage flags
 */
static int
set_key_store_args(struct subsystem_context *ele_ctx,
		   struct smw_keymgr_derive_key_args *args,
		   op_key_derivation_key_store_args_t *key_store_args,
		   unsigned int *key_group,
		   smw_attr_algo_t *actual_permitted_algo,
		   smw_attr_usage_t *actual_usage_flags)
{
	int status = SMW_STATUS_INVALID_PARAM;
	hsm_permitted_algo_t ele_permitted_algo = 0;
	struct smw_key_attributes *key_attrs = NULL;
	struct smw_keymgr_identifier *key_base_id = NULL;
	struct smw_keymgr_identifier *key_derived_id = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ele_ctx || !args || !key_store_args || !key_group ||
	    !actual_permitted_algo || !actual_usage_flags)
		goto exit;

	key_attrs = args->key_attributes;
	if (!key_attrs)
		goto exit;

	key_base_id = &args->key_base.identifier;
	key_derived_id = &args->key_derived.identifier;

	key_store_args->vers = HSM_KEY_DERIVATION_KEY_STORE_ARGS_FORMAT_VERS;
	key_store_args->rsv1 = 0;

	status = ele_get_key_store_id(&key_store_args->key_store_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_store_args->key_material_id = key_base_id->s_id;

	status = get_derived_key_type(key_derived_id->type_id,
				      &key_store_args->derived_key_type);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (SET_OVERFLOW(key_derived_id->security_size,
			 key_store_args->derived_key_bits_sz)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	status = get_key_lifetime(key_derived_id->key_attributes.attributes,
				  &key_store_args->derived_key_lifetime);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * Derived key is always transient (volatile). Use the transient
	 * key group pool managed by ele_get_key_group().
	 */
	*key_group = ELE_FIRST_TRANSIENT_KEY_GROUP;

	status = ele_get_key_group(ele_ctx, false, key_group);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (SET_OVERFLOW(*key_group, key_store_args->derived_key_group)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	ele_set_key_policy(&key_store_args->derived_key_permitted_algo,
			   &key_store_args->derived_key_usage,
			   key_attrs->permitted_algo, key_attrs->usage_flags);

	if (SET_OVERFLOW(key_store_args->derived_key_permitted_algo,
			 ele_permitted_algo)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	ele_get_key_policy(actual_permitted_algo, actual_usage_flags,
			   ele_permitted_algo,
			   key_store_args->derived_key_usage);

	key_store_args->derived_key_lifecycle = 0;
	key_store_args->derived_key_id = 0;
	key_store_args->rsv2 = 0;

	status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_hkdf_algo_args() - Set the HKDF algorithm arguments
 * @args: Pointer to internal derived key arguments structure
 * @hkdf_algo_args: Pointer to HKDF algorithm arguments structure
 * @step: HKDF step
 * @opaque: true for opaque mode (IKM/OKM are in keystore, set to NULL/0),
 *          false for plaintext mode (IKM/OKM are in user buffers)
 */
static int
set_hkdf_algo_args(struct smw_keymgr_derive_key_args *args,
		   op_key_derivation_algo_hkdf_args_t *hkdf_algo_args,
		   enum smw_hkdf_step step, bool opaque)
{
	int status = SMW_STATUS_OK;
	struct smw_keymgr_hkdf_args *hkdf_args = args->kdf_args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!hkdf_algo_args || !hkdf_args) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	hkdf_algo_args->vers = HSM_KEY_DERIVATION_ALGO_ARGS_HKDF_FORMAT_VERS;

	if (opaque) {
		hkdf_algo_args->ikm = NULL;
		hkdf_algo_args->ikm_size = 0;
		hkdf_algo_args->okm = NULL;
		hkdf_algo_args->okm_size = 0;
	} else {
		hkdf_algo_args->ikm =
			smw_keymgr_get_public_data(&args->key_base);
		hkdf_algo_args->ikm_size =
			smw_keymgr_get_public_length(&args->key_base);
		hkdf_algo_args->okm =
			smw_keymgr_get_shared_secret_buffer(&args->key_derived);
		hkdf_algo_args->okm_size =
			smw_keymgr_get_shared_secret_len(&args->key_derived);
	}

	if (step == SMW_HKDF_STEP_FULL || step == SMW_HKDF_STEP_EXTRACT) {
		hkdf_algo_args->salt = smw_keymgr_get_salt(args);
		hkdf_algo_args->salt_size = smw_keymgr_get_salt_len(args);
	} else {
		hkdf_algo_args->salt = NULL;
		hkdf_algo_args->salt_size = 0;
	}

	if (step == SMW_HKDF_STEP_FULL || step == SMW_HKDF_STEP_EXPAND) {
		hkdf_algo_args->fixed_info = smw_keymgr_get_info(args);
		hkdf_algo_args->fixed_info_size = smw_keymgr_get_info_len(args);
	} else {
		hkdf_algo_args->fixed_info = NULL;
		hkdf_algo_args->fixed_info_size = 0;
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_derived_key_id() - Set the derived key identifier after a successful
 *                        key derivation operation.
 * @args: Pointer to key derivation arguments structure
 * @key_id_derived: Pointer to derived key identifier structure
 * @key_deriv_args: Pointer to ELE key derivation arguments (contains the
 *                  returned derived_key_id)
 * @key_store_args: Pointer to key store arguments (contains the
 *                  derived_key_group)
 * @step: HKDF step that was performed
 */
static int
set_derived_key_id(struct smw_keymgr_derive_key_args *args,
		   struct smw_keymgr_identifier *key_id_derived,
		   op_key_derivation_args_t *key_deriv_args,
		   op_key_derivation_key_store_args_t *key_store_args,
		   enum smw_hkdf_step step)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_id_derived->subsystem_id = SUBSYSTEM_ID_ELE;
	key_id_derived->s_id = key_deriv_args->derived_key_id;
	key_id_derived->group = key_store_args->derived_key_group;

	/*
	 * The Extract PRK is not registered in the key manager DB; its handle
	 * is written directly to the output via smw_keymgr_set_shared_secret_id().
	 * privacy_id is only needed for DB registration, so skip the lookup.
	 */
	if (step == SMW_HKDF_STEP_EXTRACT) {
		smw_keymgr_set_shared_secret_id(&args->key_derived,
						key_id_derived->s_id);
	} else {
		status = smw_keymgr_get_privacy_id(key_id_derived->type_id,
						   &key_id_derived->privacy_id);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hkdf_opaque(struct subsystem_context *ele_ctx,
		       struct smw_keymgr_derive_key_args *args,
		       hsm_hdl_t key_mgt_hdl)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_identifier *key_id_base = NULL;
	struct smw_keymgr_identifier *key_id_derived = NULL;
	struct smw_key_attributes *key_attrs = NULL;

	enum smw_hkdf_step step = SMW_HKDF_STEP_INVALID;

	smw_attr_algo_t actual_perm_algo = 0;
	smw_attr_usage_t actual_usage = SMW_ATTR_USAGE_NONE;

	unsigned int key_group = ELE_FIRST_TRANSIENT_KEY_GROUP;

	hsm_err_t err = HSM_NO_ERROR;
	op_key_derivation_key_store_args_t key_store_args = { 0 };
	op_key_derivation_algo_hkdf_args_t hkdf_algo_args = { 0 };
	op_key_derivation_args_t key_deriv_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ele_ctx || !args)
		goto exit;

	key_id_base = &args->key_base.identifier;
	key_id_derived = &args->key_derived.identifier;
	key_attrs = args->key_attributes;

	step = smw_keymgr_get_hkdf_step(args);

	if (key_id_base->s_id == INVALID_KEY_ID) {
		SMW_DBG_PRINTF(ERROR, "Base key must be in keystore\n");
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	status = get_key_derive_algo(args->kdf_args, step,
				     &key_deriv_args.algorithm);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_deriv_args.flags = HSM_OP_KEY_DERIVATION_FLAGS_OPAQUE;

	status = set_key_store_args(ele_ctx, args, &key_store_args, &key_group,
				    &actual_perm_algo, &actual_usage);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_deriv_args.key_store_args = &key_store_args;
	key_deriv_args.key_store_args_size = sizeof(key_store_args);

	status = set_hkdf_algo_args(args, &hkdf_algo_args, step, true);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_deriv_args.key_derivation_algo_args = &hkdf_algo_args;
	key_deriv_args.key_derivation_algo_args_size = sizeof(hkdf_algo_args);

	do {
		/*
		 * Set the expected key identifier in case ELE returns
		 * KEY_GROUP_FULL. ELE erases the key identifier of
		 * the operation argument. We assume here that the key is volatile.
		 */
		key_deriv_args.derived_key_id = 0;

		if (SET_OVERFLOW(key_group, key_store_args.derived_key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto exit;
		}

		SMW_DBG_PRINTF(/* Without this comment clang-format does not */
			       /* meet the checkpatch requirement. */
			       VERBOSE,
			       "[%s (%d)] Call hsm_key_derivation() - OPAQUE\n"
			       "key_mgt_hdl: %u\n"
			       "op_key_derivation_args_t\n"
			       "  algorithm: 0x%08x\n"
			       "  flags: 0x%04x\n"
			       "  derived_key_id: 0x%08x\n"
			       "  op_key_derivation_key_store_args_t\n"
			       "    - vers: %u\n"
			       "    - key_store_id: %u\n"
			       "    - key_material_id: 0x%08x\n"
			       "    - derived_key_type: 0x%04x\n"
			       "    - derived_key_bits_sz: %u\n"
			       "    - derived_key_lifetime: 0x%08x\n"
			       "    - derived_key_usage: 0x%08x\n"
			       "    - derived_key_permitted_algo: 0x%08x\n"
			       "    - derived_key_lifecycle: 0x%08x\n"
			       "    - derived_key_id: 0x%08x\n"
			       "    - derived_key_group: %u\n"
			       "  op_key_derivation_algo_hkdf_args_t\n"
			       "    - vers: %u\n"
			       "    - ikm: %p\n"
			       "    - ikm_size: %u\n"
			       "    - salt: %p\n"
			       "    - salt_size: %u\n"
			       "    - fixed_info: %p\n"
			       "    - fixed_info_size: %u\n"
			       "    - okm: %p\n"
			       "    - okm_size: %u\n",
			       __func__, __LINE__, key_mgt_hdl,
			       key_deriv_args.algorithm, key_deriv_args.flags,
			       key_deriv_args.derived_key_id,
			       key_deriv_args.key_store_args->vers,
			       key_deriv_args.key_store_args->key_store_id,
			       key_deriv_args.key_store_args->key_material_id,
			       key_deriv_args.key_store_args->derived_key_type,
			       key_deriv_args.key_store_args
				       ->derived_key_bits_sz,
			       key_deriv_args.key_store_args
				       ->derived_key_lifetime,
			       key_deriv_args.key_store_args->derived_key_usage,
			       key_deriv_args.key_store_args
				       ->derived_key_permitted_algo,
			       key_deriv_args.key_store_args
				       ->derived_key_lifecycle,
			       key_deriv_args.key_store_args->derived_key_id,
			       key_deriv_args.key_store_args->derived_key_group,
			       key_deriv_args.key_derivation_algo_args->vers,
			       key_deriv_args.key_derivation_algo_args->ikm,
			       key_deriv_args.key_derivation_algo_args->ikm_size,
			       key_deriv_args.key_derivation_algo_args->salt,
			       key_deriv_args.key_derivation_algo_args
				       ->salt_size,
			       key_deriv_args.key_derivation_algo_args
				       ->fixed_info,
			       key_deriv_args.key_derivation_algo_args
				       ->fixed_info_size,
			       key_deriv_args.key_derivation_algo_args->okm,
			       key_deriv_args.key_derivation_algo_args
				       ->okm_size);

		err = hsm_key_derivation(key_mgt_hdl, &key_deriv_args);
		SMW_DBG_PRINTF(DEBUG, "hsm_key_derivation returned %d\n", err);

		if (err == HSM_KEY_GROUP_FULL) {
			status = ele_set_key_group_state(ele_ctx, key_group,
							 false, true);
			if (status != SMW_STATUS_OK)
				goto exit;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto exit;
			}
		}
	} while (err == HSM_KEY_GROUP_FULL);

	status = ele_convert_err(err);

	if (status == SMW_STATUS_OK)
		status = set_derived_key_id(args, key_id_derived,
					    &key_deriv_args, &key_store_args,
					    step);

exit:
	if (key_attrs && (key_attrs->usage_flags != actual_usage ||
			  key_attrs->permitted_algo != actual_perm_algo)) {
		key_attrs->usage_flags = actual_usage;
		key_attrs->permitted_algo = actual_perm_algo;

		if (status == SMW_STATUS_OK)
			status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}

static int hkdf_plaintext(struct smw_keymgr_derive_key_args *args,
			  se_lib_hdl_t se_hdl)
{
	int status = SMW_STATUS_INVALID_PARAM;

	enum smw_hkdf_step step = SMW_HKDF_STEP_INVALID;

	hsm_err_t err = HSM_NO_ERROR;
	op_key_derivation_algo_hkdf_args_t hkdf_algo_args = { 0 };
	op_key_derivation_args_t key_deriv_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	step = smw_keymgr_get_hkdf_step(args);

	status = get_key_derive_algo(args->kdf_args, step,
				     &key_deriv_args.algorithm);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_deriv_args.flags = HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT;

	/* No key store arguments for plaintext mode */
	key_deriv_args.key_store_args = NULL;
	key_deriv_args.key_store_args_size = 0;

	status = set_hkdf_algo_args(args, &hkdf_algo_args, step, false);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_deriv_args.key_derivation_algo_args = &hkdf_algo_args;
	key_deriv_args.key_derivation_algo_args_size = sizeof(hkdf_algo_args);

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_key_derivation() - PLAINTEXT\n"
		       "se_hdl: %u\n"
		       "op_key_derivation_args_t\n"
		       "  algorithm: 0x%08x\n"
		       "  flags: 0x%04X\n"
		       "  derived_key_id: 0x%08x\n"
		       "  op_key_derivation_algo_hkdf_args_t\n"
		       "    - vers: %u\n"
		       "    - ikm: %p\n"
		       "    - ikm_size: %u\n"
		       "    - salt: %p\n"
		       "    - salt_size: %u\n"
		       "    - fixed_info: %p\n"
		       "    - fixed_info_size: %u\n"
		       "    - okm: %p\n"
		       "    - okm_size: %u\n",
		       __func__, __LINE__, se_hdl, key_deriv_args.algorithm,
		       key_deriv_args.flags, key_deriv_args.derived_key_id,
		       key_deriv_args.key_derivation_algo_args->vers,
		       key_deriv_args.key_derivation_algo_args->ikm,
		       key_deriv_args.key_derivation_algo_args->ikm_size,
		       key_deriv_args.key_derivation_algo_args->salt,
		       key_deriv_args.key_derivation_algo_args->salt_size,
		       key_deriv_args.key_derivation_algo_args->fixed_info,
		       key_deriv_args.key_derivation_algo_args->fixed_info_size,
		       key_deriv_args.key_derivation_algo_args->okm,
		       key_deriv_args.key_derivation_algo_args->okm_size);

	err = hsm_key_derivation(se_hdl, &key_deriv_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_derivation returned %d\n", err);

	status = ele_convert_err(err);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int derive_hkdf(struct subsystem_context *ele_ctx,
		struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_OK;

	hsm_hdl_t key_mgt_hdl = 0;
	struct hsm_session_hdl_s *sess_ptr = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	if (args->key_base.identifier.s_id != INVALID_KEY_ID) {
		/*
		 * Opaque IKM: ELE stores the derived key in the keystore.
		 * A plaintext output buffer for the derived key is not allowed.
		 */
		if (smw_keymgr_get_shared_secret_buffer(&args->key_derived)) {
			SMW_DBG_PRINTF(/* Without this comment clang-format does not */
				       /* meet the checkpatch requirement. */
				       ERROR,
				       "Opaque IKM requires opaque derived key\n");
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}

		status = open_key_mgmt_service(&ele_ctx->hdl, &key_mgt_hdl);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = hkdf_opaque(ele_ctx, args, key_mgt_hdl);

		tmp_status = close_key_mgt_service(key_mgt_hdl);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	} else {
		/*
		 * Plaintext IKM: the derived key must be returned in a
		 * plaintext output buffer. Storing it in the keystore (opaque
		 * output) is not supported in plaintext mode.
		 */
		if (!smw_keymgr_get_shared_secret_buffer(&args->key_derived)) {
			SMW_DBG_PRINTF(/* Without this comment clang-format does not */
				       /* meet the checkpatch requirement. */
				       ERROR,
				       "Plaintext IKM requires plaintext derived key\n");
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}

		sess_ptr = session_hdl_to_ptr(ele_ctx->hdl.session);
		if (!sess_ptr) {
			status = SMW_STATUS_SUBSYSTEM_FAILURE;
			goto exit;
		}

		status = hkdf_plaintext(args, sess_ptr->se_lib_serv_hdl);
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}
