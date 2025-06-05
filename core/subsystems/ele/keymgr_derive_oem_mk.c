// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "compiler.h"
#include "debug.h"
#include "hash.h"
#include "keymgr_derive.h"
#include "utils.h"

#include "key_group.h"

#define OEM_MK_SLAT_FLAG_PEER_KEY BIT(0)
#define OEM_MK_SLAT_FLAGS_SRKH	  BIT(1)

struct __packed payload_oem_mk {
	uint8_t tag;
	uint8_t version;
	uint16_t res;
	uint32_t key_store_id;
	uint32_t key_exchange_algo;
	uint16_t derived_key_group;
	uint16_t salt_flags;
	uint16_t derived_key_type;
	uint16_t derived_key_security_size;
	uint32_t derived_key_lifetime;
	uint32_t derived_key_usage;
	uint32_t derived_key_permitted_algo;
	uint32_t derived_key_lifecycle;
	uint32_t derived_key_id;
	uint32_t private_key_id;
	uint8_t hash_peer_public_key[32];
	uint8_t hash_user_fixed_info[32];
};

#define PAYLOAD_LENGTH sizeof(struct payload_oem_mk)
#define COMMAND	       0x47
#define VERSION	       0x07

static int set_key_group_lifetime(struct subsystem_context *ele_ctx,
				  smw_attr_attributes_t attributes,
				  struct payload_oem_mk *payload)
{
	int status = SMW_STATUS_OK;

	smw_attr_attributes_t persistence =
		SMW_ATTR_GET_PERSISTENCE(attributes);
	bool persistent_grp = false;
	unsigned int key_group = 0;

	switch (persistence) {
	case SMW_ATTR_PERSISTENCE_PERSISTENT:
		payload->derived_key_lifetime = HSM_SE_KEY_STORAGE_PERSISTENT;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_PERMANENT:
		payload->derived_key_lifetime = HSM_SE_KEY_STORAGE_PERS_PERM;
		key_group = ELE_FIRST_PERSISTENT_KEY_GROUP;
		persistent_grp = true;
		break;

	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		payload->derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		key_group = ELE_FIRST_TRANSIENT_KEY_GROUP;
		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = ele_get_key_group(ele_ctx, persistent_grp, &key_group);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(key_group, payload->derived_key_group))
		status = SMW_STATUS_OPERATION_FAILURE;

end:
	// coverity[missing_unlock]
	return status;
}

static int
derive_oem_master_key_prepare(struct subsystem_context *ele_ctx,
			      struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OK;

	unsigned char *msg = NULL;
	unsigned int msg_block_length = 0;
	unsigned int msg_length = 0;
	unsigned int key_store_id = 0;
	uint16_t key_lc = 0;
	struct payload_oem_mk *payload = NULL;
	struct smw_crypto_hash_args hash_args = { 0 };
	struct smw_hash_args oneshot = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	msg_block_length = ele_get_sign_msg_block_length();
	msg_length = msg_block_length + PAYLOAD_LENGTH;
	msg = smw_keymgr_oem_get_payload(args);

	if (!msg) {
		smw_keymgr_oem_set_payload_len(args, msg_length);
		goto end;
	}

	if (smw_keymgr_oem_get_payload_len(args) < msg_length) {
		smw_keymgr_oem_set_payload_len(args, msg_length);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	ele_fill_sign_msg_block(msg, COMMAND, PAYLOAD_LENGTH);

	payload = (void *)msg + msg_block_length;

	SMW_UTILS_MEMSET(payload, 0, PAYLOAD_LENGTH);

	payload->tag = COMMAND;
	payload->version = VERSION;

	/*
	 * Set the key store id in the payload. To prevent
	 * compiler error of unaligned pointer value, need to use
	 * intermediate variable and do a memory copy.
	 */
	status = ele_get_key_store_id(&key_store_id);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_UTILS_MEMCPY(&payload->key_store_id, &key_store_id,
			 sizeof(key_store_id));

	payload->key_exchange_algo = HSM_KEY_EXCHANGE_ECDH_HKDF_SHA256;
	payload->derived_key_type = HSM_KEY_TYPE_OEM_IMPORT_MK_SK;
	payload->derived_key_security_size = 256;
	payload->derived_key_usage = HSM_KEY_USAGE_DERIVE;
	payload->derived_key_permitted_algo = PERMITTED_ALGO_HMAC_KDF_SHA256;
	payload->derived_key_id = args->key_derived.identifier.s_id;
	payload->private_key_id = args->key_base.identifier.s_id;

	status = set_key_group_lifetime(ele_ctx,
					args->key_attributes->attributes,
					payload);
	if (status != SMW_STATUS_OK)
		goto end;

	status = ele_set_lifecycle_flags(ele_ctx,
					 args->key_attributes->attributes,
					 &key_lc);
	if (status != SMW_STATUS_OK)
		goto end;

	payload->derived_key_lifecycle = key_lc;

	if (smw_keymgr_oem_use_srkh(args))
		payload->salt_flags = OEM_MK_SLAT_FLAGS_SRKH;

	if (smw_keymgr_oem_use_peer_key_digest(args))
		payload->salt_flags |= OEM_MK_SLAT_FLAG_PEER_KEY;

	/* Digest the peer public key */
	if (args->ops.get_peer(args) && args->ops.get_peer_len(args)) {
		hash_args.algo_id = SMW_CONFIG_HASH_ALGO_ID_SHA256;
		hash_args.op_step = SMW_OP_STEP_ONESHOT;
		hash_args.oneshot_pub = &oneshot;

		oneshot.algo_name = SMW_HASH_ALGO_NAME_SHA256;
		oneshot.input = args->ops.get_peer(args);
		oneshot.input_length = args->ops.get_peer_len(args);
		oneshot.output = payload->hash_peer_public_key;
		oneshot.output_length = sizeof(payload->hash_peer_public_key);

		if (!ele_hash_handle(&ele_ctx->hdl, OPERATION_ID_HASH,
				     &hash_args, &status))
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

		if (status != SMW_STATUS_OK)
			goto end;
	}

	/* Digest the user fixed information */
	if (args->ops.get_info(args) && args->ops.get_info_len(args)) {
		hash_args.algo_id = SMW_CONFIG_HASH_ALGO_ID_SHA256;
		hash_args.op_step = SMW_OP_STEP_ONESHOT;
		hash_args.oneshot_pub = &oneshot;

		oneshot.algo_name = SMW_HASH_ALGO_NAME_SHA256;
		oneshot.input = args->ops.get_info(args);
		oneshot.input_length = args->ops.get_info_len(args);
		oneshot.output = payload->hash_user_fixed_info;
		oneshot.output_length = sizeof(payload->hash_user_fixed_info);

		if (!ele_hash_handle(&ele_ctx->hdl, OPERATION_ID_HASH,
				     &hash_args, &status))
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

		if (status != SMW_STATUS_OK)
			goto end;
	}

	smw_keymgr_oem_set_payload_len(args, msg_length);

	SMW_DBG_HEX_DUMP(DEBUG, msg, msg_length, 4);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}

static int derive_oem_master_key(struct subsystem_context *ele_ctx,
				 struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OK;

	int tmp_status = SMW_STATUS_OK;
	bool srkh_fused = false;
	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_key_exchange_args_t key_ex_args = { 0 };
	struct payload_oem_mk *payload = NULL;

	status = ele_is_oem_srkh_fused(ele_ctx, &srkh_fused);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!srkh_fused) {
		status = SMW_STATUS_OEM_SRKH_NOT_FUSED;
		goto end;
	}

	payload = (struct payload_oem_mk *)smw_keymgr_oem_get_payload(args);
	if (!payload) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_SIGNED_CONTENT;
	key_ex_args.in_content = smw_keymgr_oem_get_payload(args);
	key_ex_args.in_content_sz = smw_keymgr_oem_get_payload_len(args);
	key_ex_args.in_pub_buffer = args->ops.get_peer(args);
	key_ex_args.in_pub_buffer_sz = args->ops.get_peer_len(args);
	key_ex_args.user_fixed_info = args->ops.get_info(args);
	key_ex_args.user_fixed_info_sz = args->ops.get_info_len(args);

	status = open_key_mgmt_service(&ele_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       " Call hsm_key_exchange()\n"
		       "  OEM Master Key\n"
		       "  flags: 0x%04X\n"
		       "  in_pub_buffer_sz: %d\n"
		       "  user_fixed_info_sz: %d\n"
		       "  in_content_sz: %d\n"
		       "  in_content (payload): %p\n"
		       "  out_derived_key_id: 0x%08X\n"
		       "  expected_out_sz: %d\n"
		       "  output_sz: %d\n"
		       "  output: %p\n",
		       key_ex_args.flags, key_ex_args.in_pub_buffer_sz,
		       key_ex_args.user_fixed_info_sz,
		       key_ex_args.in_content_sz, key_ex_args.in_content,
		       key_ex_args.out_derived_key_id,
		       key_ex_args.exp_output_sz, key_ex_args.output_sz,
		       key_ex_args.output);

	err = hsm_key_exchange(key_mgt_hdl, &key_ex_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	args->key_derived.identifier.group = payload->derived_key_group;
	args->key_derived.identifier.s_id = key_ex_args.out_derived_key_id;
	SMW_DBG_PRINTF(DEBUG, "OEM Master key created id=0x%08X\n",
		       args->key_derived.identifier.s_id);

end:
	if (key_mgt_hdl) {
		tmp_status = close_key_mgt_service(key_mgt_hdl);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	// coverity[missing_unlock]
	return status;
}

int derive_oem_mk(struct subsystem_context *ele_ctx,
		  struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_UNKNOWN_OP_TYPE_NAME;

	switch (smw_keymgr_oem_get_op(args)) {
	case SMW_OEM_MK_OP_NAME_PREPARE:
		status = derive_oem_master_key_prepare(ele_ctx, args);
		break;

	case SMW_OEM_MK_OP_NAME_DERIVE:
		status = derive_oem_master_key(ele_ctx, args);
		break;

	default:
		break;
	}

	// coverity[missing_unlock]
	return status;
}
