// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "debug.h"
#include "keymgr.h"
#include "utils.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_KEYMGR_PRIVACY_ID_OFFSET                                           \
	(SMW_KEY_PRIVACY_NAME_PUBLIC - SMW_KEYMGR_PRIVACY_ID_PUBLIC)

#define SMW_KEY_FORMAT_ID_OFFSET                                               \
	(SMW_KEY_FORMAT_NAME_HEX - SMW_KEYMGR_FORMAT_ID_HEX)

#define SMW_KEYMGR_FORMAT_ID_DEFAULT SMW_KEYMGR_FORMAT_ID_HEX

static int copy_rsa_key(struct smw_keypair_rsa *dst,
			struct smw_keypair_rsa *src)
{
	int status = SMW_STATUS_OK;

	if (src->modulus && src->modulus_length) {
		dst->modulus_length = src->modulus_length;
		dst->modulus = SMW_UTILS_MALLOC(dst->modulus_length);
		if (!dst->modulus) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst->modulus, src->modulus,
				 dst->modulus_length);
	}

	if (src->public_exponent && src->public_exponent_length) {
		dst->public_exponent_length = src->public_exponent_length;
		dst->public_exponent =
			SMW_UTILS_MALLOC(dst->public_exponent_length);
		if (!dst->public_exponent) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst->public_exponent, src->public_exponent,
				 dst->public_exponent_length);
	}

	if (src->public_data && src->public_length) {
		dst->public_length = src->public_length;
		dst->public_data = SMW_UTILS_MALLOC(dst->public_length);
		if (!dst->public_data) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst->public_data, src->public_data,
				 dst->public_length);
	}

	if (src->private_data && src->private_length) {
		dst->private_length = src->private_length;
		dst->private_data = SMW_UTILS_MALLOC(dst->private_length);
		if (!dst->private_data) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst->private_data, src->private_data,
				 dst->private_length);
	}

end:
	return status;
}

static int copy_gen_key(struct smw_keypair_gen *dst,
			struct smw_keypair_gen *src)
{
	int status = SMW_STATUS_OK;

	if (src->public_data && src->public_length) {
		dst->public_length = src->public_length;
		dst->public_data = SMW_UTILS_MALLOC(dst->public_length);
		if (!dst->public_data) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst->public_data, src->public_data,
				 dst->public_length);
	}

	if (src->private_data && src->private_length) {
		dst->private_length = src->private_length;
		dst->private_data = SMW_UTILS_MALLOC(dst->private_length);
		if (!dst->private_data) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst->private_data, src->private_data,
				 dst->private_length);
	}

end:
	return status;
}

static int copy_keypair_buffer(struct smw_keypair_buffer *dst,
			       struct smw_keypair_buffer *src,
			       enum smw_config_key_type_id type_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	if (!dst || !src)
		goto end;

	dst->format_name = src->format_name;

	switch (type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_NB:
	case SMW_CONFIG_KEY_TYPE_ID_INVALID:
		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		status = copy_rsa_key(&dst->rsa, &src->rsa);
		break;

	default:
		status = copy_gen_key(&dst->gen, &src->gen);
		break;
	}

end:
	return status;
}

static void free_keypair_buffer(struct smw_keypair_buffer *buf,
				enum smw_config_key_type_id type_id)
{
	if (!buf)
		return;

	switch (type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_NB:
	case SMW_CONFIG_KEY_TYPE_ID_INVALID:
		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		if (buf->rsa.modulus)
			SMW_UTILS_FREE(buf->rsa.modulus);

		if (buf->rsa.public_exponent)
			SMW_UTILS_FREE(buf->rsa.public_exponent);

		if (buf->rsa.public_data)
			SMW_UTILS_FREE(buf->rsa.public_data);

		if (buf->rsa.private_data)
			SMW_UTILS_FREE(buf->rsa.private_data);

		break;

	default:
		if (buf->gen.public_data)
			SMW_UTILS_FREE(buf->gen.public_data);

		if (buf->gen.private_data)
			SMW_UTILS_FREE(buf->gen.private_data);

		break;
	}

	SMW_UTILS_FREE(buf);
}

smw_key_privacy_t smw_utils_key_get_privacy_name(enum smw_keymgr_privacy_id id)
{
	smw_key_privacy_t name = SMW_KEY_PRIVACY_NAME_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (id < SMW_KEYMGR_PRIVACY_ID_NB &&
	    id != SMW_KEYMGR_PRIVACY_ID_INVALID)
		(void)ADD_OVERFLOW(id, SMW_KEYMGR_PRIVACY_ID_OFFSET,
				   (int *)&name);

	return name;
}

int smw_utils_key_get_format_id(smw_key_format_t name,
				enum smw_keymgr_format_id *id)
{
	int status = SMW_STATUS_UNKNOWN_FORMAT_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_KEY_FORMAT_NAME_NONE) {
		*id = SMW_KEYMGR_FORMAT_ID_DEFAULT;
		status = SMW_STATUS_OK;
	} else if (name < SMW_KEY_FORMAT_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_KEY_FORMAT_ID_OFFSET, (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

smw_key_format_t smw_utils_key_get_format_name(enum smw_keymgr_format_id id)
{
	smw_key_format_t name = SMW_KEY_FORMAT_NAME_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (id < SMW_KEYMGR_FORMAT_ID_NB && id != SMW_KEYMGR_FORMAT_ID_INVALID)
		(void)ADD_OVERFLOW(id, SMW_KEY_FORMAT_ID_OFFSET, (int *)&name);

	return name;
}

int smw_utils_key_set_hex_buffer(enum smw_keymgr_format_id format_id,
				 unsigned char *buffer, unsigned int buffer_len,
				 unsigned char **hex_buffer,
				 unsigned int *hex_buffer_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!buffer_len || !buffer || !hex_buffer || !hex_buffer_len)
		goto exit;

	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/* Convert buffer in hex format */
		status = smw_utils_base64_decode(buffer, buffer_len, hex_buffer,
						 hex_buffer_len);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Failed to decode base64\n",
				       __func__);
			goto exit;
		}
	} else {
		*hex_buffer = buffer;
		*hex_buffer_len = buffer_len;
		status = SMW_STATUS_OK;
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_key_get_hex_buffer_len(enum smw_keymgr_format_id format_id,
				     unsigned char *buffer,
				     unsigned int buffer_len,
				     unsigned int *hex_buffer_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!buffer || !buffer_len || !hex_buffer_len)
		goto exit;

	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
		*hex_buffer_len = smw_utils_get_hex_len(buffer, buffer_len);
	else
		*hex_buffer_len = buffer_len;

	status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_key_copy(struct smw_keymgr_descriptor *out,
		       struct smw_keymgr_descriptor *in)
{
	int status = SMW_STATUS_OK;
	struct smw_key_descriptor *pub = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!out || !in) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/* Copy key descriptors without public structure and ops */
	*out = *in;
	out->pub = NULL;
	SMW_UTILS_MEMSET(&out->ops, 0, sizeof(out->ops));

	/* Allocate the public key structure if any */
	if (in->pub) {
		pub = SMW_UTILS_CALLOC(1, sizeof(*pub));
		if (!pub) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		/* Copy input public key descriptor without key buffer */
		*pub = *in->pub;
		pub->buffer = NULL;
		out->pub = pub;

		if (in->pub->buffer) {
			/* Allocate the key buffers and do a copy */
			pub->buffer = SMW_UTILS_CALLOC(1, sizeof(*pub->buffer));
			if (!pub->buffer) {
				status = SMW_STATUS_ALLOC_FAILURE;
				goto end;
			}

			status = copy_keypair_buffer(pub->buffer,
						     in->pub->buffer,
						     out->identifier.type_id);
		}
	}

end:
	if (status != SMW_STATUS_OK) {
		if (pub) {
			free_keypair_buffer(pub->buffer,
					    out->identifier.type_id);

			SMW_UTILS_FREE(pub);
		}
	} else {
		out->pub = pub;
		status = setup_key_ops(out);
		if (status == SMW_STATUS_NO_KEY_BUFFER)
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_utils_key_free(struct smw_keymgr_descriptor *desc)
{
	if (!desc)
		return;

	if (desc->pub) {
		free_keypair_buffer(desc->pub->buffer,
				    desc->identifier.type_id);
		SMW_UTILS_FREE(desc->pub);
	}

	SMW_UTILS_MEMSET(desc, 0, sizeof(*desc));
}
