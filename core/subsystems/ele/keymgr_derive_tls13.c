// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include "smw_osal.h"
#include "smw_status.h"

#include "builtin_macros.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"

#include "common.h"
#include "key_group.h"

/**
 * struct tls13_ele_payload - Key Exchange input content (TLS1.3)
 * @ver: Version of this structure (should be set to 1)
 * @rsv: Reserved (should be set to 0)
 * @keystore_id: Key store ID
 * @tls1_3_algo: TLS1.3 algorithm to be used for derivation operation
 * @key_id: Base Key ID
 * @key_type: Derived Key type
 * @key_bits: Derived Key size in bits
 * @key_lifetime: Derived Key lifetime
 * @key_usage: Derived Key usage
 * @key_permitted_algo: Derived Key permitted algorithm
 * @key_lifecycle:  Derived Key lifecycle
 * @derived_key_id: Derived Key ID
 * @psk_id: Pre-Shared Key ID
 *
 * The ELE library expects that op_key_exchange_args_t.in_content is set to
 * a pointer to a structure that is specific for that key exchange operation.
 * It defines this structure layout internally, but it does not export it.
 * Define the structure here with slightly modified member names.
 *
 * @key_lifetime, @key_lifecycle and @derived_key_id are ignored.
 *
 * @key_type, @key_bits, @key_usage and @key_permitted_algo are optional, and
 * are only required when tls1_3_algo == KEYING_MATERIAL.
 *
 * @psk_id is optional, and should be used only with EARLY_SECRET.
 */
struct tls13_ele_payload {
	uint16_t ver;
	uint16_t rsv;
	uint32_t keystore_id;
	uint32_t tls1_3_algo;
	uint32_t key_id;
	uint16_t key_type;	     /* required for KEYING_MATERIAL */
	uint16_t key_bits;	     /* required for KEYING_MATERIAL */
	uint32_t key_lifetime;	     /* ignored */
	uint32_t key_usage;	     /* required for KEYING_MATERIAL */
	uint32_t key_permitted_algo; /* required for KEYING_MATERIAL */
	uint32_t key_lifecycle;	     /* ignored */
	uint32_t derived_key_id;     /* ignored */
	uint32_t psk_id;	     /* optional for EARLY_SECRET */
};

/* Maximum length of a TLS1.3 label*/
#define TLS13_LABEL_LENGTH_MAX (12)

/* Offset in expanded label where the label length is set */
#define TLS13_LABEL_LENGTH_OFFSET (2)

/* Offset in expanded label where the label is set */
#define TLS13_LABEL_OFFSET (2 + 1 + SMW_TLS13_PREFIX_LENGTH)

#define TLS13_SECRET(_label, _op_id, _hash)                                    \
	{                                                                      \
		.tls_algo = HSM_KEY_DERIVATION_TLS1_3_##_op_id##_##_hash,      \
		.label = _label, .label_len = sizeof(_label) - 1,              \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_hash,                    \
	}

static const struct {
	hsm_op_key_derivation_tls1_3_algo_t tls_algo;
	const char *label;
	unsigned int label_len;
	enum smw_config_hash_algo_id hash_id;
} tls13_secrets[] = {
	TLS13_SECRET("ext binder", EARLY_SECRET, SHA256),
	TLS13_SECRET("ext binder", EARLY_SECRET, SHA384),
	TLS13_SECRET("res binder", EARLY_SECRET, SHA256),
	TLS13_SECRET("res binder", EARLY_SECRET, SHA384),
	TLS13_SECRET("c e traffic", EARLY_SECRET, SHA256),
	TLS13_SECRET("c e traffic", EARLY_SECRET, SHA384),
	TLS13_SECRET("e exp master", EARLY_SECRET, SHA256),
	TLS13_SECRET("e exp master", EARLY_SECRET, SHA384),

	TLS13_SECRET("c hs traffic", HANDSHAKE_SECRET, SHA256),
	TLS13_SECRET("c hs traffic", HANDSHAKE_SECRET, SHA384),
	TLS13_SECRET("s hs traffic", HANDSHAKE_SECRET, SHA256),
	TLS13_SECRET("s hs traffic", HANDSHAKE_SECRET, SHA384),

	TLS13_SECRET("c ap traffic", MASTER_SECRET, SHA256),
	TLS13_SECRET("c ap traffic", MASTER_SECRET, SHA384),
	TLS13_SECRET("s ap traffic", MASTER_SECRET, SHA256),
	TLS13_SECRET("s ap traffic", MASTER_SECRET, SHA384),
	TLS13_SECRET("exp master", MASTER_SECRET, SHA256),
	TLS13_SECRET("exp master", MASTER_SECRET, SHA384),
	TLS13_SECRET("res master", MASTER_SECRET, SHA256),
	TLS13_SECRET("res master", MASTER_SECRET, SHA384),

	TLS13_SECRET("key", KEYING_MATERIAL, SHA256),
	TLS13_SECRET("key", KEYING_MATERIAL, SHA384),
	TLS13_SECRET("traffic upd", KEYING_MATERIAL, SHA256),
	TLS13_SECRET("traffic upd", KEYING_MATERIAL, SHA384),
	TLS13_SECRET("finished", KEYING_MATERIAL, SHA256),
	TLS13_SECRET("finished", KEYING_MATERIAL, SHA384),
	TLS13_SECRET("iv", IV, SHA256),
	TLS13_SECRET("iv", IV, SHA384),
	TLS13_SECRET("resumption", KEYING_MATERIAL, SHA256),
	TLS13_SECRET("resumption", KEYING_MATERIAL, SHA384),
};

static bool is_handshake_secret(unsigned int algo)
{
	return algo == HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256 ||
	       algo == HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA384;
}

static bool is_master_secret(unsigned int algo)
{
	return algo == HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256 ||
	       algo == HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA384;
}

static bool is_keying_material(unsigned int algo)
{
	return algo == HSM_KEY_DERIVATION_TLS1_3_KEYING_MATERIAL_SHA256 ||
	       algo == HSM_KEY_DERIVATION_TLS1_3_KEYING_MATERIAL_SHA384;
}

static bool is_iv(unsigned int algo)
{
	return algo == HSM_KEY_DERIVATION_TLS1_3_IV_SHA256 ||
	       algo == HSM_KEY_DERIVATION_TLS1_3_IV_SHA384;
}

static int get_tls13_attributes(struct smw_keymgr_derive_key_args *args,
				struct tls13_ele_payload *payload)
{
	struct smw_key_attributes *attr = args->key_attributes;
	hsm_key_type_t key_type = (hsm_key_type_t)0;
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (SET_OVERFLOW(args->key_derived.identifier.security_size,
			 payload->key_bits))
		goto end;

	status = ele_get_key_type(args->key_derived.identifier.type_id,
				  &key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(key_type, payload->key_type)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (attr)
		ele_set_key_policy(&payload->key_permitted_algo,
				   &payload->key_usage, attr->permitted_algo,
				   attr->usage_flags);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_tls13_algo(struct smw_keymgr_derive_key_args *args,
			  struct tls13_ele_payload *payload)
{
	int status = SMW_STATUS_INVALID_PARAM;
	size_t i = 0;
	struct smw_keymgr_tls13_args *tls13_args = args->kdf_args;
	unsigned char *info = smw_keymgr_get_info(args);
	unsigned int info_len = smw_keymgr_get_info_len(args);

	unsigned int label_len = 0;
	const char *label = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		goto end;

	if (info_len < TLS13_LABEL_LENGTH_OFFSET + 1)
		goto end;

	label_len = info[TLS13_LABEL_LENGTH_OFFSET];
	if (DEC_OVERFLOW(label_len, SMW_TLS13_PREFIX_LENGTH))
		goto end;

	if (label_len > TLS13_LABEL_LENGTH_MAX)
		goto end;

	if (info_len < TLS13_LABEL_OFFSET + label_len + 1)
		goto end;

	label = (const char *)(info + TLS13_LABEL_OFFSET);

	for (; i < ARRAY_SIZE(tls13_secrets); i++) {
		if (tls13_secrets[i].hash_id == tls13_args->prf_id &&
		    tls13_secrets[i].label &&
		    tls13_secrets[i].label_len == label_len &&
		    !SMW_UTILS_STRNCMP(tls13_secrets[i].label, label,
				       label_len)) {
			payload->tls1_3_algo = tls13_secrets[i].tls_algo;

			status = SMW_STATUS_OK;
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int tls13_set_payload_args(struct smw_keymgr_derive_key_args *args,
				  struct tls13_ele_payload **out_payload)
{
	struct tls13_ele_payload *payload = NULL;
	enum smw_status_code status = SMW_STATUS_ALLOC_FAILURE;
	struct smw_keymgr_descriptor *psk = smw_keymgr_tls13_get_psk(args);

	payload = SMW_UTILS_CALLOC(1, sizeof(*payload));
	if (!payload)
		goto end;

	if (psk->identifier.s_id) {
		if (psk->identifier.subsystem_id != SUBSYSTEM_ID_ELE) {
			status = SMW_STATUS_KEY_INVALID;
			goto end;
		}

		payload->psk_id = psk->identifier.s_id;
	}

	payload->ver = 1;
	payload->rsv = 0;
	payload->key_id = args->key_base.identifier.s_id;

	status = ele_get_key_store_id(&payload->keystore_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tls13_algo(args, payload);
	if (status != SMW_STATUS_OK)
		goto end;

	/* For Keying Material, the proper key attributes need to be set */
	if (is_keying_material(payload->tls1_3_algo)) {
		status = get_tls13_attributes(args, payload);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (is_iv(payload->tls1_3_algo)) {
		if (!smw_keymgr_get_shared_secret_buffer(&args->key_derived) ||
		    !smw_keymgr_get_shared_secret_len(&args->key_derived)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	/* Handshake/Master secrets need both the base key and peer public key */
	if (is_handshake_secret(payload->tls1_3_algo) ||
	    is_master_secret(payload->tls1_3_algo)) {
		if (!args->key_base.identifier.s_id) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		if (!smw_keymgr_get_peer_pub_buffer(args) ||
		    !smw_keymgr_get_peer_pub_buffer_len(args)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "TLS 1.3 payload:\n"
		       "    - ver: %d\n"
		       "    - keystore_id: 0x%08X\n"
		       "    - tls1_3_algo: 0x%08X\n"
		       "    - key_id: 0x%08X\n"
		       "    - key_type: 0x%08X\n"
		       "    - key_bits: %d\n"
		       "    - key_usage: 0x%08X\n"
		       "    - permitted_algo: 0x%08X\n",
		       payload->ver, payload->keystore_id, payload->tls1_3_algo,
		       payload->key_id, payload->key_type, payload->key_bits,
		       payload->key_usage, payload->key_permitted_algo);

	*out_payload = payload;

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK) {
		if (payload)
			SMW_UTILS_FREE(payload);
	}

	return status;
}

static void tls13_set_derive_args(struct smw_keymgr_derive_key_args *args,
				  struct tls13_ele_payload *payload,
				  op_key_exchange_args_t *key_ex_args)
{
	key_ex_args->flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;

	key_ex_args->in_content_sz = (unsigned int)sizeof(*payload);
	key_ex_args->in_content = (uint8_t *)payload;

	key_ex_args->output =
		smw_keymgr_get_shared_secret_buffer(&args->key_derived);
	key_ex_args->output_sz =
		smw_keymgr_get_shared_secret_len(&args->key_derived);

	key_ex_args->user_fixed_info_sz = smw_keymgr_get_info_len(args);
	key_ex_args->user_fixed_info = smw_keymgr_get_info(args);

	key_ex_args->in_pub_buffer_sz =
		smw_keymgr_get_peer_pub_buffer_len(args);
	key_ex_args->in_pub_buffer = smw_keymgr_get_peer_pub_buffer(args);
}

static void
tls13_set_derived_identifier(struct smw_keymgr_derive_key_args *args,
			     uint32_t key_id, struct tls13_ele_payload *payload)
{
	struct smw_keymgr_identifier *key_derived_identifier =
		&args->key_derived.identifier;
	struct smw_key_attributes *key_derived_attributes =
		&key_derived_identifier->key_attributes;

	if (is_iv(payload->tls1_3_algo))
		return;

	key_derived_identifier->s_id = key_id;
	/*
	 * In case of key derivation, the key group is unknown.
	 * The FW selects the key group.
	 */
	key_derived_identifier->group = ELE_UNDEFINED_KEY_GROUP;
	key_derived_identifier->security_size = payload->key_bits;
	key_derived_identifier->subsystem_id = SUBSYSTEM_ID_ELE;

	key_derived_attributes->attributes =
		SMW_ATTR_SET_SENSITIVE(key_derived_attributes->attributes);

	/*
	 * Here, both handshake secrets and master secrets are considered
	 * "TLS_MASTER" keys, because in essence there are multiple keys
	 * derived from them. For example, an encryption key used in the
	 * handshake is indirectly derived from the handshake secret.
	 */
	if (is_master_secret(payload->tls1_3_algo) ||
	    is_handshake_secret(payload->tls1_3_algo))
		key_derived_identifier->type_id =
			SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER;

	/* Hardcoded by ELE */
	key_derived_identifier->privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;

	if (smw_keymgr_is_store_key_set(args))
		return;

	smw_keymgr_set_shared_secret_id(&args->key_derived, key_id);
}

static int tls13_do_derive(struct hdl *hdl,
			   struct smw_keymgr_derive_key_args *args)
{
	enum smw_status_code status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;
	struct tls13_ele_payload *payload = NULL;
	op_key_exchange_args_t key_ex_args = { 0 };
	hsm_hdl_t key_mgt_hdl = 0;

	hsm_err_t err = HSM_NO_ERROR;

	status = tls13_set_payload_args(args, &payload);
	if (status != SMW_STATUS_OK)
		goto end;

	tls13_set_derive_args(args, payload, &key_ex_args);

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       " Call hsm_key_exchange()\n"
		       "  TLS1.3\n"
		       "  flags: 0x%04X\n"
		       "  in_pub_buffer_sz: %d\n"
		       "  user_fixed_info_sz: %d\n"
		       "  in_content_sz: %d\n"
		       "  in_content (payload): %p\n"
		       "  output_sz: %d\n"
		       "  output: %p\n",
		       key_ex_args.flags, key_ex_args.in_pub_buffer_sz,
		       key_ex_args.user_fixed_info_sz,
		       key_ex_args.in_content_sz, key_ex_args.in_content,
		       key_ex_args.output_sz, key_ex_args.output);

	err = hsm_key_exchange(key_mgt_hdl, &key_ex_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	tls13_set_derived_identifier(args, key_ex_args.out_derived_key_id,
				     payload);

end:
	if (key_mgt_hdl) {
		tmp_status = close_key_mgt_service(key_mgt_hdl);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	if (payload)
		SMW_UTILS_FREE(payload);

	return status;
}

int derive_tls13(struct hdl *hdl, struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->kdf_args)
		goto end;

	status = tls13_do_derive(hdl, args);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
