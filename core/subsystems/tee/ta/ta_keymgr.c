// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tee_subsystem.h"
#include "ta_keymgr.h"

/* Number of attributes switch key type */
#define NB_ATTR_SYMMETRIC_KEY 1
#define NB_ATTR_ECDSA_PUB_KEY 3
#define NB_ATTR_ECDSA_KEYPAIR 4

/* Persistent key object access flags */
#define PERSISTENT_KEY_FLAGS                                                   \
	(TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |              \
	 TEE_DATA_FLAG_ACCESS_WRITE_META)

/* Trusted storage space used by SMW */
#define SMW_TEE_STORAGE TEE_STORAGE_PRIVATE

/**
 * struct key_data - Key data.
 * @key_id: Key ID.
 * @handle: Key handle.
 * @is_persistent: True if key object is persistent.
 * @key_type: TEE key type.
 * @security_size: Key security size in bits.
 */
struct key_data {
	uint32_t key_id;
	TEE_ObjectHandle handle;
	bool is_persistent;
	enum tee_key_type key_type;
	unsigned int security_size;
};

/**
 * struct key_list - Key linked list structure.
 * @key_data: Current key data.
 * @next: Next key of the list.
 */
struct key_list {
	struct key_data *key_data;
	struct key_list *next;
};

/* Linked list containing transient objects and used persistent objects */
static struct key_list *key_linked_list;

/**
 * struct - Key info
 * @key_type: TEE key type.
 * @security_size: Key security size in bits.
 * @obj_type: Key TEE object type.
 * @ecc_curve: Type of ecc curve if needed.
 * @usage: TEE key cryptographic operations.
 *
 * key_info must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest for one given
 * key type ID.
 */
struct {
	enum tee_key_type key_type;
	unsigned int security_size;
	unsigned int obj_type;
	unsigned int ecc_curve;
	uint32_t usage;
} key_info[] = {
	{ .key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 192,
	  .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
	  .ecc_curve = TEE_ECC_CURVE_NIST_P192,
	  .usage = TEE_USAGE_SIGN | TEE_USAGE_VERIFY },
	{ .key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 224,
	  .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
	  .ecc_curve = TEE_ECC_CURVE_NIST_P224,
	  .usage = TEE_USAGE_SIGN | TEE_USAGE_VERIFY },
	{ .key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 256,
	  .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
	  .ecc_curve = TEE_ECC_CURVE_NIST_P256,
	  .usage = TEE_USAGE_SIGN | TEE_USAGE_VERIFY },
	{ .key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 384,
	  .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
	  .ecc_curve = TEE_ECC_CURVE_NIST_P384,
	  .usage = TEE_USAGE_SIGN | TEE_USAGE_VERIFY },
	{ .key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 521,
	  .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
	  .ecc_curve = TEE_ECC_CURVE_NIST_P521,
	  .usage = TEE_USAGE_SIGN | TEE_USAGE_VERIFY },
	{ .key_type = TEE_KEY_TYPE_ID_AES,
	  .security_size = 128,
	  .obj_type = TEE_TYPE_AES,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC },
	{ .key_type = TEE_KEY_TYPE_ID_AES,
	  .security_size = 192,
	  .obj_type = TEE_TYPE_AES,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC },
	{ .key_type = TEE_KEY_TYPE_ID_AES,
	  .security_size = 256,
	  .obj_type = TEE_TYPE_AES,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC },
	{ .key_type = TEE_KEY_TYPE_ID_DES,
	  .security_size = 64,
	  .obj_type = TEE_TYPE_DES,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC },
	{ .key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 128,
	  .obj_type = TEE_TYPE_DES3,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC },
	{ .key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 192,
	  .obj_type = TEE_TYPE_DES3,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC }
};

/**
 * get_key_obj_type() - Get key's object type.
 * @key_type: Key type.
 * @obj_type: Pointer to object type. Not updated if an error is returned.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- @obj_type is NULL.
 * TEE_ERROR_ITEM_NOT_FOUND	- Key type isn't present.
 */
static TEE_Result get_key_obj_type(enum tee_key_type key_type,
				   uint32_t *obj_type)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(key_info);

	FMSG("Executing %s", __func__);

	if (!obj_type)
		return TEE_ERROR_BAD_PARAMETERS;

	for (; i < array_size; i++) {
		if (key_info[i].key_type == key_type) {
			*obj_type = key_info[i].obj_type;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

/**
 * get_key_ecc_curve() - Get key's ecc curve.
 * @key_type: Key type.
 * @security_size: Key security size in bits.
 * @ecc_curve: Pointer to ecc curve. Not updated if an error is returned.
 *
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- @ecc_curve is NULL.
 * TEE_ERROR_NOT_SUPPORTED	- Key type/size combination isn't supported.
 */
static TEE_Result get_key_ecc_curve(enum tee_key_type key_type,
				    unsigned int security_size,
				    uint32_t *ecc_curve)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(key_info);

	FMSG("Executing %s", __func__);

	if (!ecc_curve)
		return TEE_ERROR_BAD_PARAMETERS;

	for (; i < array_size; i++) {
		if (key_info[i].key_type < key_type)
			continue;
		if (key_info[i].key_type > key_type)
			return TEE_ERROR_NOT_SUPPORTED;
		if (key_info[i].security_size < security_size)
			continue;
		if (key_info[i].security_size > security_size)
			return TEE_ERROR_NOT_SUPPORTED;

		*ecc_curve = key_info[i].ecc_curve;
		break;
	}

	return TEE_SUCCESS;
}

/**
 * key_add_list() - Add a new key to key linked list.
 * @key: Key to add to the list.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- @key is NULL.
 * TEE_ERROR_OUT_OF_MEMORY	- Malloc failed.
 */
static TEE_Result key_add_list(struct key_data *key)
{
	struct key_list *new_key = NULL;
	struct key_list *head = NULL;

	FMSG("Executing %s", __func__);

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	new_key = TEE_Malloc(sizeof(struct key_list),
			     TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!new_key) {
		EMSG("TEE_Malloc failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	new_key->key_data = key;
	new_key->next = NULL;

	if (!key_linked_list) {
		/* New key is the first of the list */
		key_linked_list = new_key;
	} else {
		head = key_linked_list;
		while (head->next)
			head = head->next;
		/* New key is the last of the list */
		head->next = new_key;
	}

	return TEE_SUCCESS;
}

/**
 * key_del_list() - Delete a key from key linked list.
 * @key: Key to remove from the list.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- @key is NULL.
 * TEE_ERROR_ITEM_NOT_FOUND	- Key not found.
 */
static TEE_Result key_del_list(struct key_data *key)
{
	struct key_list *head = NULL;
	struct key_list *prev = NULL;
	struct key_list *next = NULL;

	FMSG("Executing %s", __func__);

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	head = key_linked_list;
	prev = key_linked_list;

	while (head) {
		next = head->next;
		if (head->key_data == key) {
			if (head == key_linked_list)
				key_linked_list = next;
			else
				prev->next = next;

			TEE_Free(head->key_data);
			TEE_Free(head);

			return TEE_SUCCESS;
		}

		prev = head;
		head = next;
	};

	return TEE_ERROR_ITEM_NOT_FOUND;
}

/**
 * key_find_list() - Check if a key is present in key linked list.
 * @id: Key ID to find.
 *
 * Return:
 * Pointer to key_data structure	- Success.
 * NULL					- Key not found.
 */
static struct key_data *key_find_list(uint32_t id)
{
	struct key_list *head = key_linked_list;

	FMSG("Executing %s", __func__);

	while (head) {
		if (head->key_data->key_id == id)
			return head->key_data;

		head = head->next;
	}

	return NULL;
}

/**
 * is_persistent_key() - Check if a key is a persistent object.
 * @id: Key Id.
 * @key_handle: Pointer to key TEE_ObjectHandle. Not updated if an error is
 *              returned.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- @key_handle is NULL.
 * Error code from TEE_OpenPersistentObject().
 */
static TEE_Result is_persistent_key(uint32_t id, TEE_ObjectHandle *key_handle)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle tmp = { 0 };

	FMSG("Executing %s", __func__);

	if (!key_handle)
		return res;

	res = TEE_OpenPersistentObject(SMW_TEE_STORAGE, &id, sizeof(id),
				       PERSISTENT_KEY_FLAGS, &tmp);
	if (!res)
		*key_handle = tmp;

	return res;
}

/**
 * is_key_id_used() - Check if an ID is already used.
 * @id: ID to check.
 * @persistent: Key storage information.
 *
 * If persistent is true, check that the ID is not used in the key linked list
 * and not used by a persistent object.
 *
 * Return:
 * true		- ID is used.
 * false	- ID is not used.
 */
static bool is_key_id_used(uint32_t id, bool persistent)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle tmp_handle = { 0 };
	struct key_data *key = NULL;

	FMSG("Executing %s", __func__);

	/* Check first in the key linked list */
	key = key_find_list(id);
	if (key)
		return true;

	if (!persistent)
		return false;

	/*
	 * If !key and persistent check that ID isn't used by a
	 * persistent object
	 */
	res = is_persistent_key(id, &tmp_handle);
	if (!res)
		return true;

	return false;
}

/**
 * find_unused_id() - Find an unused key ID.
 * @id: ID to update. Not updated if an error is returned.
 * @persistent: Key storage information.
 *
 * Return:
 * TEE_SUCCESS		- Success.
 * TEE_ERROR_GENERIC	- Failed.
 */
static TEE_Result find_unused_id(uint32_t *id, bool persistent)
{
	uint32_t i = 1; /* IDs start at 1 */
	uint32_t max_id = UINT32_MAX;

	FMSG("Executing %s", __func__);

	for (; i < max_id; i++) {
		if (!is_key_id_used(i, persistent)) {
			*id = i;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_GENERIC;
}

/**
 * conf_key_attribute() - Configure key attributes.
 * @key_type: Key type.
 * @key_size: Key size in bytes.
 * @attr: Pointer to attributes to configure. Not updated if an error is
 *        returned. Allocated by this function and must be freed by caller.
 * @key: Pointer to key buffer.
 * @pubx: Pointer to public x buffer (only for ECDSA).
 * @puby: Pointer to public y buffer (only for ECDSA).
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 * Error code from get_key_ecc_curve().
 */
static TEE_Result conf_key_attribute(enum tee_key_type key_type,
				     unsigned int key_size,
				     TEE_Attribute **attr, uint8_t *key,
				     uint8_t *pubx, uint8_t *puby)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_Attribute *attributes = NULL;
	uint32_t nb_attr = 0;
	unsigned int ecc_curve = 0;
	unsigned int i = 0;
	unsigned int security_size = 0;

	FMSG("Executing %s", __func__);

	if (key_type == TEE_KEY_TYPE_ID_ECDSA) {
		if (!pubx || !puby)
			return res;
		else if (!key)
			nb_attr = NB_ATTR_ECDSA_PUB_KEY;
		else
			nb_attr = NB_ATTR_ECDSA_KEYPAIR;

		if (key_size == 66) /* 521 bits key special case */
			security_size = 521;
		else
			security_size = key_size * 8;

		res = get_key_ecc_curve(key_type, security_size, &ecc_curve);
		if (res) {
			EMSG("Can't get key ecc curve: 0x%x", res);
			return res;
		}

		*attr = TEE_Malloc(nb_attr * sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!*attr) {
			EMSG("TEE_Malloc failed");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		attributes = *attr;
		if (nb_attr == NB_ATTR_ECDSA_KEYPAIR)
			TEE_InitRefAttribute(&attributes[i++],
					     TEE_ATTR_ECC_PRIVATE_VALUE, key,
					     key_size);

		TEE_InitRefAttribute(&attributes[i++],
				     TEE_ATTR_ECC_PUBLIC_VALUE_X, pubx,
				     key_size);

		TEE_InitRefAttribute(&attributes[i++],
				     TEE_ATTR_ECC_PUBLIC_VALUE_Y, puby,
				     key_size);

		TEE_InitValueAttribute(&attributes[i], TEE_ATTR_ECC_CURVE,
				       ecc_curve, 0);
	} else { /* Symmetric-key algorithms */
		if (!key)
			return res;

		*attr = TEE_Malloc(sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!*attr) {
			EMSG("TEE_Malloc failed");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		TEE_InitRefAttribute(*attr, TEE_ATTR_SECRET_VALUE, key,
				     key_size);
	}

	return TEE_SUCCESS;
}

/**
 * set_key_usage() - Set key usage (cryptographic operations).
 * @key_type: Key type.
 * @key_handle: Key handle.
 *
 * Key are not set as extractable.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- Bad key type.
 * Error code from TEE_RestrictObjectUsage1().
 */
static TEE_Result set_key_usage(enum tee_key_type key_type,
				TEE_ObjectHandle key_handle)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(key_info);

	FMSG("Executing %s", __func__);

	for (; i < array_size; i++) {
		if (key_info[i].key_type == key_type)
			return TEE_RestrictObjectUsage1(key_handle,
							key_info[i].usage);
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result generate_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = { 0 };
	TEE_ObjectHandle persistent_key_handle = { 0 };
	TEE_Attribute *attr = NULL;
	uint32_t exp_param_types = 0;
	uint32_t object_type = 0;
	uint32_t attr_count = 0;
	unsigned int security_size = 0;
	unsigned int key_size_bytes = 0;
	uint32_t id = 0;
	uint8_t *key = NULL;
	uint8_t *pubx = NULL;
	uint8_t *puby = NULL;
	bool persistent = false;
	struct key_data *key_data = NULL;
	enum tee_key_type key_type = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Key security size (in bits) and key type
	 * params[1] = Key ID
	 * params[2] = Persistent or not
	 */
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return res;

	security_size = params[0].value.a;
	key_type = params[0].value.b;
	persistent = params[2].value.a;

	if (security_size == 521)
		key_size_bytes = 66; /* 521 bits key special case */
	else
		key_size_bytes = security_size / 8;

	/* Get TEE object type */
	res = get_key_obj_type(key_type, &object_type);
	if (res) {
		EMSG("Failed to get key object type: 0x%x", res);
		return res;
	}

	/* Find an unused ID */
	res = find_unused_id(&id, persistent);
	if (res) {
		EMSG("Failed to find an unused ID");
		return res;
	}

	/* Allocate key buffer(s) */
	key = TEE_Malloc(key_size_bytes, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!key) {
		EMSG("TEE_Malloc failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (key_type == TEE_KEY_TYPE_ID_ECDSA) {
		pubx = TEE_Malloc(2 * key_size_bytes,
				  TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!pubx) {
			EMSG("TEE_Malloc failed");
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		puby = pubx + key_size_bytes;
		attr_count = NB_ATTR_ECDSA_KEYPAIR;
	} else {
		attr_count = NB_ATTR_SYMMETRIC_KEY;
	}

	/* Configure key TEE attributes */
	res = conf_key_attribute(key_type, key_size_bytes, &attr, key, pubx,
				 puby);
	if (res) {
		EMSG("Failed to configure attribute: 0x%x", res);
		goto exit;
	}

	/* Allocate a transient object */
	res = TEE_AllocateTransientObject(object_type, security_size,
					  &key_handle);
	if (res) {
		EMSG("Failed to allocate transient object: 0x%x", res);
		goto exit;
	}

	/* Generate key */
	res = TEE_GenerateKey(key_handle, security_size, attr, attr_count);
	if (res) {
		EMSG("Failed to generate key: 0x%x", res);
		TEE_FreeTransientObject(key_handle);
		goto exit;
	}

	/* Set key usage. Make it non extractable */
	res = set_key_usage(key_type, key_handle);
	if (res) {
		EMSG("Failed to set key usage: 0x%x", res);
		TEE_FreeTransientObject(key_handle);
		goto exit;
	}

	/* Create a key data structure representing the generated key */
	key_data = TEE_Malloc(sizeof(struct key_data),
			      TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!key_data) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		TEE_FreeTransientObject(key_handle);
		goto exit;
	}

	/* Update key data fields */
	key_data->is_persistent = persistent;
	key_data->key_id = id;
	key_data->key_type = key_type;
	key_data->security_size = security_size;

	if (persistent) {
		/* Create a persistent object and free the transient object */
		res = TEE_CreatePersistentObject(SMW_TEE_STORAGE, &id,
						 sizeof(id),
						 PERSISTENT_KEY_FLAGS,
						 key_handle, NULL, 0,
						 &persistent_key_handle);
		TEE_FreeTransientObject(key_handle);

		if (res) {
			EMSG("Failed to create a persistent key: 0x%x", res);
			goto exit;
		}

		key_data->handle = persistent_key_handle;
	} else {
		key_data->handle = key_handle;
	}

	/* Add key to the linked list */
	res = key_add_list(key_data);
	if (res) {
		EMSG("Failed to add key to linked list: 0x%x", res);

		if (persistent)
			TEE_CloseAndDeletePersistentObject(key_data->handle);
		else
			TEE_FreeTransientObject(key_data->handle);
	} else {
		/* Share key ID with Normal World */
		params[1].value.a = key_data->key_id;
	}

exit:
	if (key)
		TEE_Free(key);

	if (pubx)
		TEE_Free(pubx);

	if (attr)
		TEE_Free(attr);

	if (res && key_data)
		TEE_Free(key_data);

	return res;
}

TEE_Result delete_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle persistent_handle = { 0 };
	uint32_t exp_param_types = 0;
	uint32_t id = 0;
	struct key_data *key = NULL;

	FMSG("Executing %s", __func__);

	/* params[0] = Key ID */
	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return res;

	id = params[0].value.a;

	/* Check if the key is present in the key linked list */
	key = key_find_list(id);
	if (key) {
		/* Free TEE object */
		if (key->is_persistent)
			TEE_CloseAndDeletePersistentObject(key->handle);
		else
			TEE_FreeTransientObject(key->handle);

		/* Delete key from key linked list */
		res = key_del_list(key);
		if (res)
			EMSG("Failed to delete key from linked list: 0x%x",
			     res);
	} else {
		/*
		 * Check if key is a persistent object not present in key
		 * linked list.
		 */
		res = is_persistent_key(id, &persistent_handle);
		if (!res)
			TEE_CloseAndDeletePersistentObject(persistent_handle);
	}

	return res;
}

TEE_Result clear_key_linked_list(void)
{
	TEE_Result res = TEE_SUCCESS;
	struct key_list *head = key_linked_list;
	struct key_list *next = NULL;

	FMSG("Executing %s", __func__);

	while (head) {
		next = head->next;
		if (!head->key_data->is_persistent)
			TEE_FreeTransientObject(head->key_data->handle);

		res = key_del_list(head->key_data);
		if (res) {
			EMSG("Can't delete key from linked list: 0x%x", res);
			return res;
		}

		head = next;
	}

	return res;
}
