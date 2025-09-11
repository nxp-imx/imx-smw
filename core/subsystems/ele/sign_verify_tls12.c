// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
/* ELE calculates the verify_data through the Key Exchange API */
#include "keymgr_derive_tls12.h"

#include "common.h"

#define CLIENT_FINISHED_STR ((unsigned char *)"client finished")
#define CLIENT_FINISHED_LEN (15)
#define SERVER_FINISHED_STR ((unsigned char *)"server finished")
#define SERVER_FINISHED_LEN (15)

#define TLS1_2_SIGN_TYPE(_type_id)                                             \
	{                                                                      \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_type_id,                 \
		.label = _type_id##_FINISHED_STR,                              \
		.label_len = _type_id##_FINISHED_LEN                           \
	}

#define TLS1_2_VERIFY_ALGO(_algo_id)                                           \
	{                                                                      \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_algo_id,                 \
		.ele_algo = HSM_KEY_DERIVATION_TLS1_2_VERIFY_DATA_##_algo_id   \
	}

static const struct signature_type {
	enum smw_config_sign_type_id type_id;
	unsigned char *label;
	unsigned int label_len;
} sign_type_list[] = { TLS1_2_SIGN_TYPE(CLIENT), TLS1_2_SIGN_TYPE(SERVER) };

static const struct tls1_2_verify_algo {
	enum smw_config_hash_algo_id algo_id;
	hsm_op_key_derivation_tls1_2_algo_t ele_algo;
} verify_algo_list[] = { TLS1_2_VERIFY_ALGO(SHA256),
			 TLS1_2_VERIFY_ALGO(SHA384) };

static int set_tls1_2_label(enum smw_config_sign_type_id type_id,
			    unsigned char **label, unsigned int *label_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(sign_type_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (sign_type_list[i].type_id == type_id) {
			*label = sign_type_list[i].label;
			*label_len = sign_type_list[i].label_len;

			SMW_DBG_PRINTF(DEBUG, "ELE TLS1.2 label: %s\n", *label);

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int set_tls1_2_verify_algo(enum smw_config_hash_algo_id algo_id,
				  hsm_op_key_derivation_tls1_2_algo_t *ele_algo)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(verify_algo_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (verify_algo_list[i].algo_id == algo_id) {
			*ele_algo = verify_algo_list[i].ele_algo;

			SMW_DBG_PRINTF(DEBUG,
				       "ELE TLS1.2 verify algorithm: %d\n",
				       *ele_algo);

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int tls_mac_finish(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	struct tls12_kb_ele_op_payload payload = { 0 };
	op_key_exchange_args_t key_ex_args = { 0 };

	unsigned char *label = NULL;
	unsigned int label_len = 0;

	struct smw_crypto_sign_verify_args *smw_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&smw_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	unsigned char *msg = NULL;
	unsigned int msg_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	payload.ver = 1;
	payload.key_id = key_identifier->s_id;

	status = ele_get_key_store_id(&payload.keystore_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = set_tls1_2_label(smw_args->attributes.type_id, &label,
				  &label_len);
	if (status != SMW_STATUS_OK)
		goto end;

	status = set_tls1_2_verify_algo(smw_args->attributes.hash_id,
					&payload.tls1_2_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	msg = smw_sign_verify_get_msg_buf(smw_args);
	msg_len = smw_sign_verify_get_msg_len(smw_args);
	if (!msg || !msg_len) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (ADD_OVERFLOW(label_len, msg_len, &key_ex_args.user_fixed_info_sz)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_ex_args.user_fixed_info =
		SMW_UTILS_CALLOC(1, key_ex_args.user_fixed_info_sz);
	if (!key_ex_args.user_fixed_info) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	SMW_UTILS_MEMCPY(key_ex_args.user_fixed_info, label, label_len);
	SMW_UTILS_MEMCPY(key_ex_args.user_fixed_info + label_len, msg, msg_len);

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = (uint32_t)sizeof(payload);
	key_ex_args.in_content = (uint8_t *)&payload;
	key_ex_args.output_sz = smw_sign_verify_get_sign_len(smw_args);
	key_ex_args.output = smw_sign_verify_get_sign_buf(smw_args);

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       " Call hsm_key_exchange() - TLS1.2 MAC FINISH\n"
		       "  flags: 0x%04X\n"
		       "  in_pub_buffer_sz: %d\n"
		       "  user_fixed_info_sz: %d\n"
		       "  in_content_sz: %d\n"
		       "  in_content: %p\n"
		       "  payload params (ignored fields omitted)\n"
		       "    - ver: %d\n"
		       "    - keystore_id: %d\n"
		       "    - tls1_2_algo: 0x%x\n"
		       "    - key_id: 0x%08X\n"
		       "    - cipher_bits: %d\n"
		       "    - cipher_algo: 0x%08X\n"
		       "    - derived_key_id: %d\n"
		       "  out_derived_key_id: 0x%08X\n"
		       "  expected_out_sz: %d\n"
		       "  output_sz: %d\n"
		       "  output: %p\n",
		       key_ex_args.flags, key_ex_args.in_pub_buffer_sz,
		       key_ex_args.user_fixed_info_sz,
		       key_ex_args.in_content_sz, key_ex_args.in_content,
		       payload.ver, payload.keystore_id, payload.tls1_2_algo,
		       payload.key_id, payload.cipher_bits, payload.cipher_algo,
		       payload.derived_key_id, key_ex_args.out_derived_key_id,
		       key_ex_args.exp_output_sz, key_ex_args.output_sz,
		       key_ex_args.output);

	err = hsm_key_exchange(key_mgt_hdl, &key_ex_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);
	status = ele_convert_err(err);

	smw_sign_verify_set_sign_len(smw_args, key_ex_args.output_sz);

end:
	tmp_status = close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	if (key_ex_args.user_fixed_info)
		SMW_UTILS_FREE(key_ex_args.user_fixed_info);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}
