// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "keymgr.h"
#include "object_db.h"
#include "utils.h"

static int object_to_key_identifier(struct smw_object_descriptor *obj,
				    struct smw_keymgr_identifier *identifier)
{
	int status = SMW_STATUS_OK;

	status = smw_config_get_subsystem_id(obj->subsystem_name,
					     &identifier->subsystem_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(obj->key.type_name,
					    &identifier->type_id);
	if (status != SMW_STATUS_OK)
		return status;

	switch (obj->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		identifier->privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
		break;
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		identifier->privacy_id = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
		break;
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		identifier->privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;
		break;
	default:
		break;
	}

	identifier->security_size = obj->key.security_size;
	identifier->key_attributes = obj->key.attributes;
	if (SET_OVERFLOW(obj->group, identifier->group))
		status = SMW_STATUS_INVALID_PARAM;

	return status;
}

static void key_identifier_to_object(unsigned int u_id,
				     struct smw_keymgr_identifier *identifier,
				     struct smw_object_descriptor *obj)
{
	int status = SMW_STATUS_OK;
	enum smw_keymgr_privacy_id privacy = identifier->privacy_id;
	enum smw_keymgr_privacy_id default_privacy =
		SMW_KEYMGR_PRIVACY_ID_INVALID;

	if (identifier->type_id != SMW_CONFIG_KEY_TYPE_ID_INVALID) {
		status = smw_keymgr_get_privacy_id(identifier->type_id,
						   &default_privacy);
		if (status != SMW_STATUS_OK)
			return;
	}

	if (privacy == SMW_KEYMGR_PRIVACY_ID_INVALID)
		privacy = default_privacy;

	switch (privacy) {
	case SMW_KEYMGR_PRIVACY_ID_PAIR:
		obj->type = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		break;

	case SMW_KEYMGR_PRIVACY_ID_PUBLIC:
		obj->type = SMW_OBJECT_TYPE_NAME_PUBLIC_KEY;
		break;

	case SMW_KEYMGR_PRIVACY_ID_PRIVATE:
		if (default_privacy == SMW_KEYMGR_PRIVACY_ID_PAIR)
			obj->type = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		else
			obj->type = SMW_OBJECT_TYPE_NAME_SECRET_KEY;
		break;

	case SMW_KEYMGR_PRIVACY_ID_SHARED_SECRET:
		obj->type = SMW_OBJECT_TYPE_NAME_SECRET_KEY;
		break;

	default:
		break;
	}

	obj->id = u_id;
	obj->key.id = u_id;

	if (identifier->subsystem_id == SUBSYSTEM_ID_INVALID)
		obj->subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
	else
		obj->subsystem_name =
			smw_config_get_subsystem_name(identifier->subsystem_id);

	obj->key.type_name = smw_config_get_key_type_name(identifier->type_id);
	obj->key.security_size = identifier->security_size;
	obj->key.attributes = identifier->key_attributes;
	obj->group = identifier->group;
}

int smw_keymgr_db_create(unsigned int *u_id,
			 struct smw_keymgr_identifier *identifier)
{
	int status = SMW_STATUS_OK;

	struct smw_object_descriptor obj = { 0 };

	/*
	 * Create a key in database using the same id as the one define in
	 * by user. If id = 0, database will return an database id and
	 * subsystem will assign its own id.
	 */
	*u_id = identifier->s_id;

	key_identifier_to_object(*u_id, identifier, &obj);

	if (NXP_IS_EL2GO_OBJECT(identifier->key_attributes.storage_id))
		obj.label = KEY_DEFAULT_EL2GO_LABEL;
	else
		obj.label = KEY_DEFAULT_LABEL;

	status = smw_object_db_create(identifier->s_id, &obj);

	if (status == SMW_STATUS_OK)
		*u_id = obj.id;

	return status;
}

static int convert_buffer_hex(enum smw_config_key_type_id type_id,
			      struct smw_keypair_buffer *buffer,
			      struct smw_keypair_buffer **hex_buf)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	struct smw_keypair_buffer *tmp_buf = NULL;

	unsigned char *in = NULL;
	unsigned int in_len = 0;
	unsigned char **out = NULL;
	unsigned int *out_len = NULL;

	tmp_buf = SMW_UTILS_CALLOC(1, sizeof(*tmp_buf));
	if (!tmp_buf)
		goto end;

	tmp_buf->format_name = SMW_KEY_FORMAT_NAME_HEX;

	if (type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		if (buffer->rsa.public_data && buffer->rsa.public_length) {
			in = buffer->rsa.public_data;
			in_len = buffer->rsa.public_length;
			out = &tmp_buf->rsa.public_data;
			out_len = &tmp_buf->rsa.public_length;

			status = smw_utils_base64_decode(in, in_len, out,
							 out_len);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		if (buffer->rsa.modulus && buffer->rsa.modulus_length) {
			in = buffer->rsa.modulus;
			in_len = buffer->rsa.modulus_length;
			out = &tmp_buf->rsa.modulus;
			out_len = &tmp_buf->rsa.modulus_length;

			status = smw_utils_base64_decode(in, in_len, out,
							 out_len);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		if (buffer->rsa.public_exponent &&
		    buffer->rsa.public_exponent_length) {
			in = buffer->rsa.public_exponent;
			in_len = buffer->rsa.public_exponent_length;
			out = &tmp_buf->rsa.public_exponent;
			out_len = &tmp_buf->rsa.public_exponent_length;

			status = smw_utils_base64_decode(in, in_len, out,
							 out_len);
			if (status != SMW_STATUS_OK)
				goto end;
		}
	} else {
		if (buffer->gen.public_data && buffer->gen.public_length) {
			in = buffer->gen.public_data;
			in_len = buffer->gen.public_length;
			out = &tmp_buf->gen.public_data;
			out_len = &tmp_buf->gen.public_length;

			status = smw_utils_base64_decode(in, in_len, out,
							 out_len);
			if (status != SMW_STATUS_OK)
				goto end;
		}
	}

	*hex_buf = tmp_buf;

end:
	if (status != SMW_STATUS_OK && tmp_buf)
		smw_utils_free_keypair_buffer(type_id, tmp_buf);

	return status;
}

int smw_keymgr_db_update(unsigned int u_id,
			 struct smw_keymgr_identifier *identifier,
			 struct smw_keypair_buffer *buffer)
{
	int status = SMW_STATUS_OK;
	struct smw_object_descriptor obj = { 0 };
	struct smw_keypair_buffer *hex_buf = NULL;
	smw_osal_db_capability_t cap = SMW_OSAL_DB_CAPABILITY_PUBLIC_KEY_IMPORT;

	key_identifier_to_object(u_id, identifier, &obj);

	if (identifier->s_id != INVALID_KEY_ID)
		return smw_object_db_update(identifier->s_id, &obj);

	if (identifier->privacy_id != SMW_KEYMGR_PRIVACY_ID_PUBLIC) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_osal_obj_db_has_capability(cap);
	if (status != SMW_STATUS_OK)
		goto end;

	if (buffer->format_name != SMW_KEY_FORMAT_NAME_BASE64) {
		obj.key.buffer = buffer;
	} else {
		status = convert_buffer_hex(identifier->type_id, buffer,
					    &hex_buf);
		if (status != SMW_STATUS_OK)
			goto end;

		obj.key.buffer = hex_buf;
	}

	status = smw_object_db_update(identifier->s_id, &obj);

end:
	if (hex_buf)
		smw_utils_free_keypair_buffer(identifier->type_id, hex_buf);

	return status;
}

int smw_keymgr_db_delete(unsigned int u_id,
			 struct smw_keymgr_identifier *identifier)
{
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(u_id, identifier, &obj);

	return smw_object_db_delete(&obj);
}

int smw_keymgr_db_get_info(unsigned int u_id,
			   struct smw_keymgr_identifier *identifier)
{
	int ret = SMW_STATUS_OK;
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(u_id, identifier, &obj);

	ret = smw_object_db_get_info(&identifier->s_id, &obj);
	if (ret == SMW_STATUS_OK) {
		switch (obj.type) {
		case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
			ret = object_to_key_identifier(&obj, identifier);
			break;

		default:
			ret = SMW_STATUS_UNKNOWN_ID;
			break;
		}
	}

	smw_object_db_clean_descriptor(&obj);

	return ret;
}

int smw_keymgr_db_get_buffer(unsigned int u_id,
			     struct smw_keymgr_identifier *identifier,
			     struct smw_keypair_buffer **buffer)
{
	int ret = SMW_STATUS_OK;
	struct smw_object_descriptor obj = { 0 };

	key_identifier_to_object(u_id, identifier, &obj);

	ret = smw_object_db_get_info(&u_id, &obj);
	if (ret != SMW_STATUS_OK)
		goto end;

	if (!obj.key.buffer)
		goto end;

	/* Transfer ownership of the buffer */
	*buffer = obj.key.buffer;
	obj.key.buffer = NULL;

end:
	smw_object_db_clean_descriptor(&obj);

	return ret;
}
