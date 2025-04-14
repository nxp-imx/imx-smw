// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_keymgr.h"
#include "smw_status.h"

#include "debug.h"
#include "operations.h"
#include "keymgr_derive.h"
#include "utils.h"

/**
 * smw_keymgr_oem_get_peer_pub_buffer() - Get peer public key buffer address
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Address of peer public key buffer
 */
static unsigned char *
smw_keymgr_oem_get_peer_pub_buffer(struct smw_keymgr_derive_key_args *args)
{
	unsigned char *buffer = NULL;
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		buffer = oem_mk_args->pub_args->peer_public_buffer;

	return buffer;
}

/**
 * smw_keymgr_oem_get_peer_pub_buffer_len() - Get peer public key buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Length of peer public key buffer
 */
static unsigned int
smw_keymgr_oem_get_peer_pub_buffer_len(struct smw_keymgr_derive_key_args *args)
{
	unsigned int length = 0;
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		length = oem_mk_args->pub_args->peer_public_buffer_length;

	return length;
}

/**
 * smw_keymgr_oem_get_info() - Get user information buffer address
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Address of user information buffer
 */
static unsigned char *
smw_keymgr_oem_get_info(struct smw_keymgr_derive_key_args *args)
{
	unsigned char *buffer = NULL;
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		buffer = oem_mk_args->pub_args->info;

	return buffer;
}

/**
 * smw_keymgr_oem_get_info_len() - Get user information buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Length of user information buffer
 */
static unsigned int
smw_keymgr_oem_get_info_len(struct smw_keymgr_derive_key_args *args)
{
	unsigned int length = 0;
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		length = oem_mk_args->pub_args->info_len;

	return length;
}

/**
 * oem_mk_validate_key_base() - Validate base key
 * @args: Pointer to internal key derivation arguments structure
 *
 * Return:
 * SMW_STATUS_OK              - Success
 * SMW_STATUS_INVALID_PARAM   - Invalid function parameter
 */
static int oem_mk_validate_key_base(struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier *identifier = &args->key_base.identifier;

	status = smw_keymgr_get_privacy_id(identifier->type_id,
					   &identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

unsigned char *
smw_keymgr_oem_get_payload(struct smw_keymgr_derive_key_args *args)
{
	unsigned char *buffer = NULL;
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		buffer = oem_mk_args->pub_args->payload;

	return buffer;
}

unsigned int
smw_keymgr_oem_get_payload_len(struct smw_keymgr_derive_key_args *args)
{
	unsigned int length = 0;
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		length = oem_mk_args->pub_args->payload_length;

	return length;
}

void smw_keymgr_oem_set_payload_len(struct smw_keymgr_derive_key_args *args,
				    unsigned int length)
{
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		oem_mk_args->pub_args->payload_length = length;
}

smw_oem_master_key_op_t
smw_keymgr_oem_get_op(struct smw_keymgr_derive_key_args *args)
{
	smw_oem_master_key_op_t op = SMW_OEM_MK_OP_NAME_NONE;

	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		op = oem_mk_args->pub_args->op;

	return op;
}

bool smw_keymgr_oem_use_srkh(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;
	bool flag = false;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		flag = oem_mk_args->pub_args->use_oem_srkh_kdf;

	return flag;
}

bool smw_keymgr_oem_use_peer_key_digest(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;
	bool flag = false;

	SMW_DBG_ASSERT(args && args->kdf_args);

	oem_mk_args = args->kdf_args;

	if (oem_mk_args->pub_args)
		flag = oem_mk_args->pub_args->use_peer_key_digest_kdf;

	return flag;
}

int smw_keymgr_oem_mk_convert_input(struct smw_derive_key_args *args,
				    struct smw_keymgr_derive_key_args *conv_args,
				    enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_key_descriptor *base_key_desc = NULL;
	struct smw_keymgr_oem_mk_args *oem_mk_args = NULL;
	struct smw_kdf_oem_master_key_args *pub_kdf_args = NULL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}
	if (!args->kdf_arguments)
		goto end;

	pub_kdf_args = args->kdf_arguments;

	if (pub_kdf_args->op != SMW_OEM_MK_OP_NAME_PREPARE &&
	    pub_kdf_args->op != SMW_OEM_MK_OP_NAME_DERIVE)
		goto end;

	base_key_desc = args->key_descriptor_base;

	/* Get the input key base for the derivation */
	status = smw_keymgr_convert_descriptor(base_key_desc,
					       &conv_args->key_base, false,
					       subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = oem_mk_validate_key_base(conv_args);
	if (status != SMW_STATUS_OK)
		goto end;

	oem_mk_args = SMW_UTILS_CALLOC(1, sizeof(*oem_mk_args));
	if (!oem_mk_args) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	oem_mk_args->pub_args = pub_kdf_args;

	conv_args->kdf_args = oem_mk_args;
	conv_args->ops.get_peer = smw_keymgr_oem_get_peer_pub_buffer;
	conv_args->ops.get_peer_len = smw_keymgr_oem_get_peer_pub_buffer_len;
	conv_args->ops.get_info = smw_keymgr_oem_get_info;
	conv_args->ops.get_info_len = smw_keymgr_oem_get_info_len;

end:

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}
