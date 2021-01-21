// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tee_subsystem.h"
#include "ta_keymgr.h"

/* Number of attributes switch key type */
#define NB_ATTR_ECDSA_PUB_KEY 3
#define NB_ATTR_ECDSA_KEYPAIR 4
#define NB_ATTR_SYMM_KEY      1

/* Persistent key object access flags */
#define PERSISTENT_KEY_FLAGS                                                   \
	(TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |              \
	 TEE_DATA_FLAG_ACCESS_WRITE_META)

/* Trusted storage space used by SMW */
#define SMW_TEE_STORAGE TEE_STORAGE_PRIVATE

/**
 * struct key_data - Key data.
 * @key_id: Key ID.
 * @handle: Key handle (only for transient object).
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
	  .security_size = 56,
	  .obj_type = TEE_TYPE_DES,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC },
	{ .key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 112,
	  .obj_type = TEE_TYPE_DES3,
	  .ecc_curve = 0,
	  .usage = TEE_MODE_ENCRYPT | TEE_USAGE_DECRYPT | TEE_USAGE_MAC },
	{ .key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 168,
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
	if (!res) {
		TEE_CloseObject(tmp_handle);
		return true;
	}

	return false;
}

/**
 * find_unused_id() - Find an unused key ID.
 * @id: ID to update. Not updated if an error is returned.
 * @persistent: Key storage information.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_ITEM_NOT_FOUND	- Failed.
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

	EMSG("Failed to find an unused ID");
	return TEE_ERROR_ITEM_NOT_FOUND;
}

/**
 * conf_key_ecc_attribute() - Configure key ECC attribute.
 * @key_type: Key type.
 * @security_size: Key security size.
 * @attr: Pointer to attribute to configure. Not updated if an error is
 *        returned.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 * Error code from get_key_ecc_curve().
 */
static TEE_Result conf_key_ecc_attribute(enum tee_key_type key_type,
					 unsigned int security_size,
					 TEE_Attribute *attr)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	unsigned int ecc_curve = 0;

	FMSG("Executing %s", __func__);

	if (!attr)
		return res;

	res = get_key_ecc_curve(key_type, security_size, &ecc_curve);
	if (res) {
		EMSG("Can't get key ecc curve: 0x%x", res);
		return res;
	}

	TEE_InitValueAttribute(attr, TEE_ATTR_ECC_CURVE, ecc_curve, 0);

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

/**
 * shift_public_key() - Right shift public key buffer.
 * @key_size: Key size in bytes.
 * @size: Key size returned by TEE_GetObjectBufferAttribute.
 * @pub_key: Public key buffer.
 *
 * Beginning of @pub_key is set to 0.
 *
 * Return:
 * none.
 */
static void shift_public_key(unsigned int key_size, unsigned int size,
			     unsigned char *pub_key)
{
	unsigned int shift = key_size - size;

	memmove(pub_key + shift, pub_key, size);
	memset(pub_key, 0, shift);
}

/**
 * export_pub_key_ecc() - Export asymmetric public key.
 * @handle: Key handle.
 * @security_size: Key security size.
 * @pub_key: Pointer to public key buffer.
 * @pub_key_size: @pub_key size (bytes).
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from TEE_GetObjectBufferAttribute().
 */
static TEE_Result export_pub_key_ecc(TEE_ObjectHandle handle,
				     unsigned int security_size,
				     unsigned char *pub_key,
				     unsigned int pub_key_size)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	unsigned int key_size_bytes = 0;
	unsigned int size = 0;

	FMSG("Executing %s", __func__);

	if (!pub_key)
		return res;

	key_size_bytes = BITS_TO_BYTES_SIZE(security_size);

	/* Public key size is twice private key size */
	if (pub_key_size != 2 * key_size_bytes) {
		EMSG("Invalid pub key size: %d (%d expected)", pub_key_size,
		     2 * key_size_bytes);
		return res;
	}

	/* Get first part of public key */
	size = key_size_bytes;
	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   pub_key, &size);
	if (res) {
		EMSG("TEE_GetObjectBufferAttribute returned 0x%x", res);
		return res;
	}

	if (size < key_size_bytes)
		shift_public_key(key_size_bytes, size, pub_key);

	/* Get second part of the public key */
	size = key_size_bytes;
	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
					   pub_key + key_size_bytes, &size);
	if (res) {
		EMSG("TEE_GetObjectBufferAttribute returned 0x%x", res);
		return res;
	}

	if (size < key_size_bytes)
		shift_public_key(key_size_bytes, size,
				 pub_key + key_size_bytes);

	return res;
}

/**
 * set_ecc_public_key() - Set ecc public key attributes.
 * @attr: Pointer to TEE Attrbute structure to update.
 * @key: Public key.
 * @key_len: @ken length in bytes.
 *
 * Return:
 * None.
 */
static inline void set_ecc_public_key(TEE_Attribute *attr, unsigned char *key,
				      unsigned int key_len)
{
	TEE_InitRefAttribute(attr, TEE_ATTR_ECC_PUBLIC_VALUE_X, key,
			     key_len / 2);

	TEE_InitRefAttribute(&attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     key + key_len / 2, key_len / 2);
}

/**
 * set_import_key_public_attributes() - Set import attributes for public key.
 * @attr: TEE Attribute structure to allocate and set.
 * @attr_count: Number of attributes to set.
 * @key_type: Key type.
 * @security_size: Key security size.
 * @pub_key: Pointer to public key buffer.
 * @pub_key_len: @pub_key length in bytes.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 * Error code from conf_key_ecc_attribute().
 */
static TEE_Result set_import_key_public_attributes(TEE_Attribute **attr,
						   uint32_t attr_count,
						   enum tee_key_type key_type,
						   unsigned int security_size,
						   unsigned char *pub_key,
						   unsigned int pub_key_len)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_Attribute *key_attr = NULL;

	FMSG("Executing %s", __func__);

	key_attr = TEE_Malloc(attr_count * sizeof(TEE_Attribute),
			      TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!key_attr) {
		EMSG("TEE_Malloc failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	*attr = key_attr;

	res = conf_key_ecc_attribute(key_type, security_size, key_attr++);
	if (res != TEE_SUCCESS) {
		TEE_Free(*attr);
		*attr = NULL;
		return res;
	}

	set_ecc_public_key(key_attr, pub_key, pub_key_len);

	return TEE_SUCCESS;
}

/**
 * set_import_keypair_attributes() - Set import attributes for keypair.
 * @attr: TEE Attribute structure to allocate and set.
 * @attr_count: Number of attributes to set.
 * @key_type: Key type.
 * @security_size: Key security size.
 * @priv_key: Pointer to private key buffer.
 * @priv_key_len: @priv_key length in bytes.
 * @pub_key: Pointer to public key buffer.
 * @pub_key_len: @pub_key length in bytes.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 * Error code from conf_key_ecc_attribute().
 */
static TEE_Result set_import_keypair_attributes(
	TEE_Attribute **attr, uint32_t attr_count, enum tee_key_type key_type,
	unsigned int security_size, unsigned char *priv_key,
	unsigned int priv_key_len, unsigned char *pub_key,
	unsigned int pub_key_len)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_Attribute *key_attr = NULL;

	FMSG("Executing %s", __func__);

	key_attr = TEE_Malloc(attr_count * sizeof(TEE_Attribute),
			      TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!key_attr) {
		EMSG("TEE_Malloc failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	*attr = key_attr;

	res = conf_key_ecc_attribute(key_type, security_size, key_attr++);
	if (res != TEE_SUCCESS) {
		TEE_Free(*attr);
		*attr = NULL;
		return res;
	}

	TEE_InitRefAttribute(key_attr++, TEE_ATTR_ECC_PRIVATE_VALUE, priv_key,
			     priv_key_len);

	set_ecc_public_key(key_attr, pub_key, pub_key_len);

	return TEE_SUCCESS;
}

/**
 * set_import_key_private_attributes() - Set import attributes for private key.
 * @attr: TEE Attribute structure to allocate and set.
 * @attr_count: Number of attributes to set.
 * @priv_key: Pointer to private key buffer.
 * @priv_key_len: @priv_key length in bytes.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 */
static TEE_Result set_import_key_private_attributes(TEE_Attribute **attr,
						    uint32_t attr_count,
						    unsigned char *priv_key,
						    unsigned int priv_key_len)
{
	FMSG("Executing %s", __func__);

	*attr = TEE_Malloc(attr_count * sizeof(TEE_Attribute),
			   TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!*attr) {
		EMSG("TEE_Malloc failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_InitRefAttribute(*attr, TEE_ATTR_SECRET_VALUE, priv_key,
			     priv_key_len);

	return TEE_SUCCESS;
}

/**
 * set_import_key_attributes() - Set import key attributes.
 * @attr: Pointer to TEE Attribute structure. Allocated by sub function. Must
 *        be freed by the caller if function returned SUCCESS.
 * @attr_count: Pointer to the number of attributes set.
 * @object_type: TEE object type.
 * @security_size: Key security size.
 * @priv_key: Pointer to private key buffer. Can be NULL.
 * @priv_key_len: @priv_key length in bytes.
 * @pub_key: Pointer to public key buffer. Can be NULL.
 * @pub_key_len: @pub_key length in bytes.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is bad.
 * Error code from set_import_key_public_attributes().
 * Error code from set_import_keypair_attributes().
 * Error code from set_import_key_private_attributes().
 */
static TEE_Result
set_import_key_attributes(TEE_Attribute **attr, uint32_t *attr_count,
			  uint32_t object_type, unsigned int security_size,
			  unsigned char *priv_key, unsigned int priv_key_len,
			  unsigned char *pub_key, unsigned int pub_key_len)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	FMSG("Executing %s", __func__);

	if (!attr || !attr_count || (!priv_key && !pub_key))
		return res;

	switch (object_type) {
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
		*attr_count = NB_ATTR_ECDSA_PUB_KEY;
		return set_import_key_public_attributes(attr,
							NB_ATTR_ECDSA_PUB_KEY,
							TEE_KEY_TYPE_ID_ECDSA,
							security_size, pub_key,
							pub_key_len);

	case TEE_TYPE_ECDSA_KEYPAIR:
		*attr_count = NB_ATTR_ECDSA_KEYPAIR;
		return set_import_keypair_attributes(attr,
						     NB_ATTR_ECDSA_KEYPAIR,
						     TEE_KEY_TYPE_ID_ECDSA,
						     security_size, priv_key,
						     priv_key_len, pub_key,
						     pub_key_len);

	case TEE_TYPE_AES:
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
		*attr_count = NB_ATTR_SYMM_KEY;
		return set_import_key_private_attributes(attr, NB_ATTR_SYMM_KEY,
							 priv_key,
							 priv_key_len);

	default:
		return res;
	}
}

/**
 * get_import_key_obj_type() - Get key's object type for import key operation.
 * @key_type: Key type.
 * @obj_type: Pointer to object type. Not updated if an error is returned.
 * @priv_key: Pointer to private key. Can be NULL.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- @obj_type is NULL.
 * Error code from get_key_obj_type().
 */
static TEE_Result get_import_key_obj_type(enum tee_key_type key_type,
					  uint32_t *obj_type, void *priv_key)
{
	FMSG("Executing %s", __func__);

	if (!obj_type)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key_type == TEE_KEY_TYPE_ID_ECDSA && !priv_key) {
		*obj_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
		return TEE_SUCCESS;
	}

	return get_key_obj_type(key_type, obj_type);
}

TEE_Result generate_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle pers_key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr = {};
	uint32_t object_type = 0;
	uint32_t attr_count = 0;
	unsigned int security_size = 0;
	uint32_t id = 0;
	uint8_t *pub_key = NULL;
	uint32_t pub_key_size = 0;
	bool persistent = false;
	struct key_data *key_data = NULL;
	enum tee_key_type key_type = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Key security size (in bits) and key type
	 * params[1] = Key ID
	 * params[2] = Persistent or not
	 * params[3] = Key buffer or none
	 */

	if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_VALUE_OUTPUT,
					   TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
		pub_key = params[3].memref.buffer;
		pub_key_size = params[3].memref.size;
	} else if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_VALUE_OUTPUT,
						  TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_NONE)) {
		pub_key = NULL;
		pub_key_size = 0;
	} else {
		return res;
	}

	security_size = params[0].value.a;
	key_type = params[0].value.b;
	persistent = params[2].value.a;

	/* Get TEE object type */
	res = get_key_obj_type(key_type, &object_type);
	if (res) {
		EMSG("Failed to get key object type: 0x%x", res);
		return res;
	}

	/* Find an unused ID */
	res = find_unused_id(&id, persistent);
	if (res)
		return res;

	/* Configure key ECC attribute */
	if (key_type == TEE_KEY_TYPE_ID_ECDSA) {
		res = conf_key_ecc_attribute(key_type, security_size,
					     &key_attr);
		if (res) {
			EMSG("Failed to configure key ecc attribute: 0x%x",
			     res);
			return res;
		}

		attr_count = 1;
	}

	/* Allocate a transient object */
	res = TEE_AllocateTransientObject(object_type, security_size,
					  &key_handle);
	if (res) {
		EMSG("Failed to allocate transient object: 0x%x", res);
		return res;
	}

	/* Generate key */
	res = TEE_GenerateKey(key_handle, security_size, &key_attr, attr_count);
	if (res) {
		EMSG("Failed to generate key: 0x%x", res);
		goto err;
	}

	/* Set key usage. Make it non extractable */
	res = set_key_usage(key_type, key_handle);
	if (res) {
		EMSG("Failed to set key usage: 0x%x", res);
		goto err;
	}

	/* Create a key data structure representing the generated key */
	key_data = TEE_Malloc(sizeof(struct key_data),
			      TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!key_data) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* Update key data fields */
	key_data->is_persistent = persistent;
	key_data->key_id = id;
	key_data->key_type = key_type;
	key_data->security_size = security_size;

	/* Export ECC public key */
	if (key_type == TEE_KEY_TYPE_ID_ECDSA && pub_key) {
		res = export_pub_key_ecc(key_handle, security_size, pub_key,
					 pub_key_size);
		if (res) {
			EMSG("Failed to export public key: 0x%x", res);
			goto err;
		}
	}

	if (persistent) {
		/* Create a persistent object and free the transient object */
		res = TEE_CreatePersistentObject(SMW_TEE_STORAGE, &id,
						 sizeof(id),
						 PERSISTENT_KEY_FLAGS,
						 key_handle, NULL, 0,
						 &pers_key_handle);
		TEE_FreeTransientObject(key_handle);
		key_handle = TEE_HANDLE_NULL;

		if (res) {
			EMSG("Failed to create a persistent key: 0x%x", res);
			goto err;
		}

		key_data->handle = NULL;
		TEE_CloseObject(pers_key_handle);
	} else {
		key_data->handle = key_handle;
	}

	/* Add key to the linked list */
	res = key_add_list(key_data);
	if (!res) {
		/* Share key ID with Normal World */
		params[1].value.a = key_data->key_id;
		return res;
	}

err:
	if (key_data)
		TEE_Free(key_data);

	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);

	if (pers_key_handle != TEE_HANDLE_NULL)
		res = TEE_CloseAndDeletePersistentObject1(pers_key_handle);

	return res;
}

TEE_Result delete_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle hdl = { 0 };
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
		/* If key is persisent, try to open it and close/delete it */
		if (key->is_persistent) {
			res = is_persistent_key(id, &hdl);
			if (!res) {
				res = TEE_CloseAndDeletePersistentObject1(hdl);
				if (res) {
					EMSG("Failed to delete key: 0x%x", res);
					return res;
				}
			} else {
				EMSG("Failed to open persistent object: 0x%x",
				     res);
				return res;
			}
		} else {
			TEE_FreeTransientObject(key->handle);
		}

		/* Delete key from key linked list */
		res = key_del_list(key);
		if (res)
			EMSG("Failed to delete key from linked list: 0x%x",
			     res);

		return res;
	}

	/* Close and delete persistent object not present in the list */
	res = is_persistent_key(id, &hdl);
	if (!res) {
		res = TEE_CloseAndDeletePersistentObject1(hdl);
		if (res)
			EMSG("Failed to delete persistent key: 0x%x", res);
	} else {
		EMSG("Failed to open persistent object: 0x%x", res);
	}

	return res;
}

TEE_Result import_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle pers_handle = TEE_HANDLE_NULL;
	TEE_Attribute *key_attr = NULL;
	uint32_t object_type = 0;
	uint32_t attr_count = 0;
	uint32_t id = 0;
	unsigned int security_size = 0;
	unsigned int priv_key_len = 0;
	unsigned int pub_key_len = 0;
	unsigned char *priv_key = NULL;
	unsigned char *pub_key = NULL;
	bool persistent = false;
	struct key_data *key_data = NULL;
	enum tee_key_type key_type = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Key security size (in bits) and key type
	 * params[1] = Persistent or not, key ID
	 * params[2] = Private key buffer
	 * params[3] = Public key buffer
	 */
	if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_VALUE_INOUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT)) {
		/* Asymmetric Keypair */
		priv_key = params[2].memref.buffer;
		priv_key_len = params[2].memref.size;
		pub_key = params[3].memref.buffer;
		pub_key_len = params[3].memref.size;
	} else if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_VALUE_INOUT,
						  TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_NONE)) {
		/* Symmetric Key */
		priv_key = params[2].memref.buffer;
		priv_key_len = params[2].memref.size;
	} else if (param_types ==
		   TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				   TEE_PARAM_TYPE_VALUE_INOUT,
				   TEE_PARAM_TYPE_NONE,
				   TEE_PARAM_TYPE_MEMREF_INPUT)) {
		/* Asymmetric Public key */
		pub_key = params[3].memref.buffer;
		pub_key_len = params[3].memref.size;
	} else {
		return res;
	}

	security_size = params[0].value.a;
	key_type = params[0].value.b;
	persistent = params[1].value.a;

	/* Get TEE object type */
	res = get_import_key_obj_type(key_type, &object_type, priv_key);
	if (res) {
		EMSG("Failed to get key object type: 0x%x", res);
		return res;
	}

	/* Find an unused ID */
	res = find_unused_id(&id, persistent);
	if (res)
		return res;

	/* Setup key attributes */
	res = set_import_key_attributes(&key_attr, &attr_count, object_type,
					security_size, priv_key, priv_key_len,
					pub_key, pub_key_len);
	if (res)
		return res;

	/* Allocate a transient object */
	res = TEE_AllocateTransientObject(object_type, security_size,
					  &key_handle);
	if (res) {
		EMSG("Failed to allocate transient object: 0x%x", res);
		goto exit;
	}

	/* Populate transient object */
	res = TEE_PopulateTransientObject(key_handle, key_attr, attr_count);
	if (res) {
		EMSG("Failed to populate transient object: 0x%x", res);
		goto exit;
	}

	/* Set key usage. Make it non extractable */
	res = set_key_usage(key_type, key_handle);
	if (res) {
		EMSG("Failed to set key usage: 0x%x", res);
		goto exit;
	}

	/* Create a key data structure representing the imported key */
	key_data = TEE_Malloc(sizeof(struct key_data),
			      TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!key_data) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
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
						 &pers_handle);
		TEE_FreeTransientObject(key_handle);
		key_handle = TEE_HANDLE_NULL;

		if (res) {
			EMSG("Failed to create a persistent key: 0x%x", res);
			goto exit;
		}

		key_data->handle = NULL;
		TEE_CloseObject(pers_handle);
	} else {
		key_data->handle = key_handle;
	}

	/* Add key to the linked list */
	res = key_add_list(key_data);

exit:
	if (res) {
		if (key_data)
			TEE_Free(key_data);

		if (key_handle != TEE_HANDLE_NULL)
			TEE_FreeTransientObject(key_handle);

		if (pers_handle != TEE_HANDLE_NULL)
			res = TEE_CloseAndDeletePersistentObject1(pers_handle);
	} else {
		/* Share key ID with Normal World */
		params[1].value.b = key_data->key_id;
	}

	if (key_attr)
		TEE_Free(key_attr);

	return res;
}

TEE_Result export_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	uint32_t id = 0;
	unsigned int security_size = 0;
	unsigned int pub_key_len = 0;
	bool persistent = false;
	unsigned char *pub_key = NULL;
	struct key_data *key_data = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = TEE Key ID, Key security size.
	 * params[1] = Key buffer.
	 * params[2] = None.
	 * params[3] = None.
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return res;

	id = params[0].value.a;
	security_size = params[0].value.b;
	pub_key = params[1].memref.buffer;
	pub_key_len = params[1].memref.size;

	key_data = key_find_list(id);
	if (key_data) {
		if (key_data->is_persistent) {
			res = is_persistent_key(id, &key_handle);
			if (res) {
				EMSG("Failed to open persistent object: 0x%x",
				     res);
				return res;
			}

			persistent = true;
		} else {
			key_handle = key_data->handle;
		}
	} else {
		res = is_persistent_key(id, &key_handle);
		if (res)
			return res;

		persistent = true;
	}

	res = export_pub_key_ecc(key_handle, security_size, pub_key,
				 pub_key_len);

	if (persistent)
		TEE_CloseObject(key_handle);

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
