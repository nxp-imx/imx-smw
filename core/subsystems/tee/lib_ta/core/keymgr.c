// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tee_subsystem.h"
#include "keymgr.h"

/* Number of attributes switch key type */
#define NB_ATTR_ECDSA_PUB_KEY 3
#define NB_ATTR_ECDSA_KEYPAIR 4
#define NB_ATTR_RSA_PUB_KEY   2
#define NB_ATTR_RSA_KEYPAIR   3
#define NB_ATTR_SYMM_KEY      1

/* Persistent key object access flags */
#define PERSISTENT_KEY_FLAGS                                                   \
	(TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |              \
	 TEE_DATA_FLAG_ACCESS_WRITE_META)

/* Trusted storage space used by SMW */
#define SMW_TEE_STORAGE TEE_STORAGE_PRIVATE

#define SECURITY_SIZE_RANGE UINT_MAX

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
 * struct - Key usage conversion
 * @usage: Input key usage value
 * @tee_usage: TEE key usage constant
 *
 * Array of the TEE versus TA input key usage definition
 */
struct {
	unsigned int usage;
	uint32_t tee_usage;
} conv_key_usage[] = { { TEE_KEY_USAGE_EXPORTABLE, TEE_USAGE_EXTRACTABLE },
		       { TEE_KEY_USAGE_COPYABLE, 0 },
		       { TEE_KEY_USAGE_ENCRYPT, TEE_USAGE_ENCRYPT },
		       { TEE_KEY_USAGE_DECRYPT, TEE_USAGE_DECRYPT },
		       { TEE_KEY_USAGE_SIGN, TEE_USAGE_SIGN },
		       { TEE_KEY_USAGE_VERIFY, TEE_USAGE_VERIFY },
		       { TEE_KEY_USAGE_DERIVE, TEE_USAGE_DERIVE },
		       { TEE_KEY_USAGE_MAC, TEE_USAGE_MAC } };

/**
 * struct - Key info
 * @key_type: TEE key type.
 * @security_size: Key security size in bits.
 * @obj_type: Key TEE object type.
 * @ecc_curve: Type of ecc curve if needed.
 *
 * key_info must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest for one given
 * key type ID.
 * If @security_size in set to SECURITY_SIZE_RANGE, the size is a range of value
 * and the field is not used.
 */
struct {
	enum tee_key_type key_type;
	unsigned int security_size;
	unsigned int obj_type;
	unsigned int ecc_curve;
} key_info[] = { { .key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 192,
		   .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
		   .ecc_curve = TEE_ECC_CURVE_NIST_P192 },
		 { .key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 224,
		   .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
		   .ecc_curve = TEE_ECC_CURVE_NIST_P224 },
		 { .key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 256,
		   .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
		   .ecc_curve = TEE_ECC_CURVE_NIST_P256 },
		 { .key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 384,
		   .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
		   .ecc_curve = TEE_ECC_CURVE_NIST_P384 },
		 { .key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 521,
		   .obj_type = TEE_TYPE_ECDSA_KEYPAIR,
		   .ecc_curve = TEE_ECC_CURVE_NIST_P521 },
		 { .key_type = TEE_KEY_TYPE_ID_AES,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_AES,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_DES,
		   .security_size = 56,
		   .obj_type = TEE_TYPE_DES,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_DES3,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_DES3,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_HMAC_MD5,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_HMAC_MD5,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_HMAC_SHA1,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_HMAC_SHA1,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_HMAC_SHA224,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_HMAC_SHA224,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_HMAC_SHA256,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_HMAC_SHA256,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_HMAC_SHA384,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_HMAC_SHA384,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_HMAC_SHA512,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_HMAC_SHA512,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_HMAC_SM3,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_HMAC_SM3,
		   .ecc_curve = 0 },
		 { .key_type = TEE_KEY_TYPE_ID_RSA,
		   .security_size = SECURITY_SIZE_RANGE,
		   .obj_type = TEE_TYPE_RSA_KEYPAIR,
		   .ecc_curve = 0 } };

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
	TEE_ObjectHandle tmp_handle = TEE_HANDLE_NULL;
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
 * convert_key_usage() - Convert a TA param key usage to TEE key usage
 * @key_usage: Key usage to convert
 * @tee_key_usage: TEE key usage value
 *
 * Return:
 * TEE_SUCCESS                - Success.
 * TEE_ERROR_BAD_PARAMETERS   - Bad key type.
 */
static TEE_Result convert_key_usage(unsigned int key_usage,
				    uint32_t *tee_key_usage)
{
	unsigned int i;

	FMSG("Executing %s", __func__);

	if (!key_usage)
		return TEE_ERROR_BAD_PARAMETERS;

	*tee_key_usage = 0;
	for (i = 0; i < ARRAY_SIZE(conv_key_usage); i++) {
		if (conv_key_usage[i].usage & key_usage)
			*tee_key_usage |= conv_key_usage[i].tee_usage;
	}

	if (!*tee_key_usage)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

/**
 * set_key_usage() - Set key usage (cryptographic operations).
 * @key_usage: Key usage definition.
 * @key_handle: Key handle.
 *
 * Key are not set as extractable.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- Bad key type.
 * Error code from TEE_RestrictObjectUsage1().
 */
static TEE_Result set_key_usage(uint32_t key_usage, TEE_ObjectHandle key_handle)
{
	FMSG("Executing %s", __func__);

	if (!key_usage)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_RestrictObjectUsage1(key_handle, key_usage);
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
 * @pub_key_size: Pointer to @pub_key size (bytes).
 *
 * Return:
 * TEE_SUCCESS		- Success.
 * TEE_ERROR_NO_DATA	- @pub_key is not set.
 * Error code from TEE_GetObjectBufferAttribute().
 */
static TEE_Result export_pub_key_ecc(TEE_ObjectHandle handle,
				     unsigned int security_size,
				     unsigned char *pub_key,
				     unsigned int *pub_key_size)
{
	TEE_Result res = TEE_ERROR_NO_DATA;
	unsigned int key_size_bytes = 0;
	unsigned int size = 0;

	FMSG("Executing %s", __func__);

	if (!pub_key)
		return res;

	key_size_bytes = BITS_TO_BYTES_SIZE(security_size);

	/* Public key size is twice private key size */
	if (*pub_key_size != 2 * key_size_bytes) {
		EMSG("Invalid pub key size: %d (%d expected)", *pub_key_size,
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

	*pub_key_size = size;

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

	*pub_key_size += size;

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
 * set_import_keypair_attrs() - Set import attributes for keypair.
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
static TEE_Result
set_import_keypair_attrs(TEE_Attribute **attr, uint32_t attr_count,
			 enum tee_key_type key_type, unsigned int security_size,
			 unsigned char *priv_key, unsigned int priv_key_len,
			 unsigned char *pub_key, unsigned int pub_key_len)
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
 * set_rsa_public_key() - Set the rsa public key attributes (modulus and
 *                        public exponent)
 * @attr: Pointer to TEE Attrbute structure to update.
 * @modulus: Modulus buffer.
 * @modulus_len: @modulus length in bytes.
 * @pub_exp: Public exponent buffer.
 * @pub_len: @pub_key length in bytes.
 *
 * Return:
 * none
 */
static inline void set_rsa_public_key(TEE_Attribute *attr,
				      unsigned char *modulus,
				      unsigned int modulus_len,
				      unsigned char *pub_exp,
				      unsigned int pub_len)
{
	TEE_InitRefAttribute(attr, TEE_ATTR_RSA_MODULUS, modulus, modulus_len);

	TEE_InitRefAttribute(&attr[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, pub_exp,
			     pub_len);
}

/**
 * set_import_key_rsa_attributes() - Set the import key rsa attributes.
 * @attr: TEE Attribute structure to allocate and set.
 * @attr_count: Number of attributes to set.
 * @modulus: Modulus buffer.
 * @modulus_len: @modulus length in bytes.
 * @pub_exp: Public exponent buffer.
 * @pub_len: @pub_key length in bytes.
 * @priv_exp: Private exponent buffer.
 * @priv_len: @priv_key length in bytes.
 *
 * RSA public key is composed of modulus and public exponent.
 * RSA keypair is composed of RSA public key and private exponent.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 */
static TEE_Result
set_import_key_rsa_attributes(TEE_Attribute **attr, uint32_t attr_count,
			      unsigned char *modulus, unsigned int modulus_len,
			      unsigned char *pub_exp, unsigned int pub_len,
			      unsigned char *priv_exp, unsigned int priv_len)
{
	TEE_Attribute *key_attr = NULL;

	FMSG("Executing %s", __func__);

	key_attr = TEE_Malloc(attr_count * sizeof(TEE_Attribute),
			      TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!key_attr) {
		EMSG("TEE_Malloc failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	*attr = key_attr;

	if (attr_count == NB_ATTR_RSA_KEYPAIR)
		TEE_InitRefAttribute(key_attr++, TEE_ATTR_RSA_PRIVATE_EXPONENT,
				     priv_exp, priv_len);

	set_rsa_public_key(key_attr, modulus, modulus_len, pub_exp, pub_len);

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
 * @modulus: Pointer to modulus buffer. Can be NULL.
 * @modulus_len: @modulus length in bytes.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is bad.
 * Error code from set_import_key_public_attributes().
 * Error code from set_import_keypair_attrs().
 * Error code from set_import_key_private_attributes().
 * Error code from set_import_key_rsa_attributes().
 */
static TEE_Result
set_import_key_attributes(TEE_Attribute **attr, uint32_t *attr_count,
			  uint32_t object_type, unsigned int security_size,
			  unsigned char *priv_key, unsigned int priv_key_len,
			  unsigned char *pub_key, unsigned int pub_key_len,
			  unsigned char *modulus, unsigned int modulus_len)
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
		return set_import_keypair_attrs(attr, NB_ATTR_ECDSA_KEYPAIR,
						TEE_KEY_TYPE_ID_ECDSA,
						security_size, priv_key,
						priv_key_len, pub_key,
						pub_key_len);

	case TEE_TYPE_RSA_PUBLIC_KEY:
		*attr_count = NB_ATTR_RSA_PUB_KEY;
		return set_import_key_rsa_attributes(attr, NB_ATTR_RSA_PUB_KEY,
						     modulus, modulus_len,
						     pub_key, pub_key_len, NULL,
						     0);

	case TEE_TYPE_RSA_KEYPAIR:
		*attr_count = NB_ATTR_RSA_KEYPAIR;
		return set_import_key_rsa_attributes(attr, NB_ATTR_RSA_KEYPAIR,
						     modulus, modulus_len,
						     pub_key, pub_key_len,
						     priv_key, priv_key_len);

	case TEE_TYPE_AES:
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_HMAC_SM3:
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

	if (key_type == TEE_KEY_TYPE_ID_RSA && !priv_key) {
		*obj_type = TEE_TYPE_RSA_PUBLIC_KEY;
		return TEE_SUCCESS;
	}

	return get_key_obj_type(key_type, obj_type);
}

/**
 * set_key_rsa_attribute() - Set RSA key attribute.
 * @pub_exp: Pointer to public exponent buffer.
 * @pub_exp_len: @pub_exp length in bytes.
 * @attr: Pointer to TEE Attribute structure to fill.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 */
static TEE_Result set_key_rsa_attribute(unsigned char *pub_exp,
					size_t pub_exp_len, TEE_Attribute *attr)
{
	FMSG("Executing %s", __func__);

	if (!attr)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_InitRefAttribute(attr, TEE_ATTR_RSA_PUBLIC_EXPONENT, pub_exp,
			     pub_exp_len);

	return TEE_SUCCESS;
}

/**
 * export_pub_key_rsa() - Export RSA public key.
 * @handle: Key handle.
 * @modulus: Pointer to modulus buffer.
 * @modulus_len: Pointer to @modulus length in bytes.
 * @pub_exp: Pointer to public exponent buffer.
 * @pub_exp_len: Pointer to @pub_exp length in bytes.
 *
 * Return:
 * TEE_SUCCESS		- Success.
 * TEE_ERROR_NO_DATA	- @modulus and @pub_exp are not set.
 * Error code from TEE_GetObjectBufferAttribute().
 */
static TEE_Result export_pub_key_rsa(TEE_ObjectHandle handle,
				     unsigned char *modulus,
				     unsigned int *modulus_len,
				     unsigned char *pub_exp,
				     unsigned int *pub_exp_len)
{
	TEE_Result res = TEE_ERROR_NO_DATA;

	FMSG("Executing %s", __func__);

	if (!(modulus && pub_exp))
		return res;

	/* Get modulus */
	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_RSA_MODULUS,
					   modulus, modulus_len);
	if (res) {
		EMSG("TEE_GetObjectBufferAttribute returned 0x%x", res);
		return res;
	}

	/* Get public exponent */
	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_RSA_PUBLIC_EXPONENT,
					   pub_exp, pub_exp_len);
	if (res)
		EMSG("TEE_GetObjectBufferAttribute returned 0x%x", res);

	return res;
}

TEE_Result generate_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle pers_key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr = { 0 };
	uint32_t object_type = 0;
	uint32_t attr_count = 0;
	unsigned int security_size = 0;
	uint32_t id = 0;
	unsigned char *pub_key = NULL;
	unsigned char *modulus = NULL;
	unsigned char *rsa_pub_exp_attr = NULL;
	uint32_t *pub_key_size = NULL;
	uint32_t *modulus_size = NULL;
	size_t rsa_pub_exp_attr_len = 0;
	bool persistent = false;
	struct key_data *key_data = NULL;
	struct keymgr_shared_params *shared_params = NULL;
	enum tee_key_type key_type = 0;
	uint32_t key_usage = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Pointer to generate shared params structure.
	 * params[1] = Pointer to public key buffer or none.
	 * params[2] = Pointer to modulus buffer (RSA) or none.
	 * params[3] = Pointer to public exponent attribute (RSA) or none.
	 */
	if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
		return res;

	if (params[0].memref.size != sizeof(*shared_params) ||
	    !params[0].memref.buffer)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, GEN_PUB_KEY_PARAM_IDX) ==
	    TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		pub_key = params[GEN_PUB_KEY_PARAM_IDX].memref.buffer;
		pub_key_size = &params[GEN_PUB_KEY_PARAM_IDX].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, GEN_PUB_KEY_PARAM_IDX) !=
		   TEE_PARAM_TYPE_NONE) {
		return res;
	}

	if (TEE_PARAM_TYPE_GET(param_types, GEN_MOD_PARAM_IDX) ==
	    TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		modulus = params[GEN_MOD_PARAM_IDX].memref.buffer;
		modulus_size = &params[GEN_MOD_PARAM_IDX].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, GEN_MOD_PARAM_IDX) !=
		   TEE_PARAM_TYPE_NONE) {
		return res;
	}

	if (TEE_PARAM_TYPE_GET(param_types, GEN_PUB_EXP_PARAM_IDX) ==
	    TEE_PARAM_TYPE_MEMREF_INPUT) {
		rsa_pub_exp_attr = params[GEN_PUB_EXP_PARAM_IDX].memref.buffer;
		rsa_pub_exp_attr_len =
			params[GEN_PUB_EXP_PARAM_IDX].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, GEN_PUB_EXP_PARAM_IDX) !=
		   TEE_PARAM_TYPE_NONE) {
		return res;
	}

	shared_params = params[0].memref.buffer;
	security_size = shared_params->security_size;
	key_type = shared_params->key_type;
	persistent = shared_params->persistent_storage;

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

	if (key_type == TEE_KEY_TYPE_ID_ECDSA) {
		/* Configure key ECC attribute */
		res = conf_key_ecc_attribute(key_type, security_size,
					     &key_attr);
		if (res) {
			EMSG("Failed to configure key ecc attribute: 0x%x",
			     res);
			return res;
		}

		attr_count = 1;
	} else if (key_type == TEE_KEY_TYPE_ID_RSA && rsa_pub_exp_attr) {
		/* Configure RSA public exponent attribute */
		res = set_key_rsa_attribute(rsa_pub_exp_attr,
					    rsa_pub_exp_attr_len, &key_attr);

		if (res) {
			EMSG("Failed to configure RSA key attribute");
			return res;
		}

		attr_count = 1;
	}

	res = convert_key_usage(shared_params->key_usage, &key_usage);
	if (res) {
		EMSG("Key usage 0x%08X is not valid", shared_params->key_usage);
		return res;
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
	res = set_key_usage(key_usage, key_handle);
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

	if (key_type == TEE_KEY_TYPE_ID_RSA)
		/* Export RSA public key */
		res = export_pub_key_rsa(key_handle, modulus, modulus_size,
					 pub_key, pub_key_size);
	else if (key_type == TEE_KEY_TYPE_ID_ECDSA)
		/* Export ECDSA public key */
		res = export_pub_key_ecc(key_handle, security_size, pub_key,
					 pub_key_size);

	if (res != TEE_SUCCESS && res != TEE_ERROR_NO_DATA) {
		EMSG("Failed to export public key: 0x%x", res);
		goto err;
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
		shared_params->id = key_data->key_id;
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

TEE_Result ta_import_key(TEE_ObjectHandle *key_handle,
			 enum tee_key_type key_type, unsigned int security_size,
			 uint32_t key_usage, unsigned char *priv_key,
			 unsigned int priv_key_len, unsigned char *pub_key,
			 unsigned int pub_key_len, unsigned char *modulus,
			 unsigned int modulus_len)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_Attribute *key_attr = NULL;
	uint32_t object_type = 0;
	uint32_t attr_count = 0;

	FMSG("Executing %s", __func__);

	/* Get TEE object type */
	res = get_import_key_obj_type(key_type, &object_type, priv_key);
	if (res) {
		EMSG("Failed to get key object type: 0x%x", res);
		return res;
	}

	/* Setup key attributes */
	res = set_import_key_attributes(&key_attr, &attr_count, object_type,
					security_size, priv_key, priv_key_len,
					pub_key, pub_key_len, modulus,
					modulus_len);
	if (res)
		goto exit;

	/* Allocate a transient object */
	res = TEE_AllocateTransientObject(object_type, security_size,
					  key_handle);
	if (res) {
		EMSG("Failed to allocate transient object: 0x%x", res);
		goto exit;
	}

	/* Populate transient object */
	res = TEE_PopulateTransientObject(*key_handle, key_attr, attr_count);
	if (res) {
		EMSG("Failed to populate transient object: 0x%x", res);
		goto exit;
	}

	/* Set key usage. Make it non extractable */
	res = set_key_usage(key_usage, *key_handle);
	if (res)
		EMSG("Failed to set key usage: 0x%x", res);

exit:
	if (key_attr)
		TEE_Free(key_attr);

	return res;
}

TEE_Result import_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle pers_handle = TEE_HANDLE_NULL;
	uint32_t id = 0;
	unsigned int security_size = 0;
	unsigned int priv_key_len = 0;
	unsigned int pub_key_len = 0;
	unsigned int modulus_len = 0;
	unsigned char *priv_key = NULL;
	unsigned char *pub_key = NULL;
	unsigned char *modulus = NULL;
	bool persistent = false;
	struct key_data *key_data = NULL;
	struct keymgr_shared_params *shared_params = NULL;
	enum tee_key_type key_type = 0;
	uint32_t key_usage = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0]: Pointer to import shared params structure.
	 * params[1]: Private key buffer or none.
	 * params[2]: Public key buffer or none.
	 * params[3]: Modulus buffer (RSA) or none.
	 */
	if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
		return res;

	if (params[0].memref.size != sizeof(*shared_params) ||
	    !params[0].memref.buffer)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, IMP_PRIV_KEY_PARAM_IDX) ==
	    TEE_PARAM_TYPE_MEMREF_INPUT) {
		priv_key = params[IMP_PRIV_KEY_PARAM_IDX].memref.buffer;
		priv_key_len = params[IMP_PRIV_KEY_PARAM_IDX].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, IMP_PRIV_KEY_PARAM_IDX) !=
		   TEE_PARAM_TYPE_NONE) {
		return res;
	}

	if (TEE_PARAM_TYPE_GET(param_types, IMP_PUB_KEY_PARAM_IDX) ==
	    TEE_PARAM_TYPE_MEMREF_INPUT) {
		pub_key = params[IMP_PUB_KEY_PARAM_IDX].memref.buffer;
		pub_key_len = params[IMP_PUB_KEY_PARAM_IDX].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, IMP_PUB_KEY_PARAM_IDX) !=
		   TEE_PARAM_TYPE_NONE) {
		return res;
	}

	if (TEE_PARAM_TYPE_GET(param_types, IMP_MOD_PARAM_IDX) ==
	    TEE_PARAM_TYPE_MEMREF_INPUT) {
		modulus = params[IMP_MOD_PARAM_IDX].memref.buffer;
		modulus_len = params[IMP_MOD_PARAM_IDX].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, IMP_MOD_PARAM_IDX) !=
		   TEE_PARAM_TYPE_NONE) {
		return res;
	}

	shared_params = params[0].memref.buffer;
	security_size = shared_params->security_size;
	key_type = shared_params->key_type;
	persistent = shared_params->persistent_storage;

	/* Find an unused ID */
	res = find_unused_id(&id, persistent);
	if (res)
		return res;

	res = convert_key_usage(shared_params->key_usage, &key_usage);
	if (res) {
		EMSG("Key usage 0x%08X is not valid", shared_params->key_usage);
		return res;
	}

	res = ta_import_key(&key_handle, key_type, security_size, key_usage,
			    priv_key, priv_key_len, pub_key, pub_key_len,
			    modulus, modulus_len);
	if (res) {
		EMSG("Failed to import key: 0x%x", res);
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
		shared_params->id = key_data->key_id;
	}

	return res;
}

TEE_Result ta_get_key_handle(TEE_ObjectHandle *key_handle, uint32_t key_id,
			     bool *persistent)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct key_data *key_data = NULL;

	if (!key_handle || !persistent)
		return res;

	*persistent = false;

	key_data = key_find_list(key_id);
	if (key_data && !key_data->is_persistent) {
		*key_handle = key_data->handle;
		res = TEE_SUCCESS;
	} else {
		res = is_persistent_key(key_id, key_handle);
		if (!res)
			*persistent = true;
	}

	return res;
}

TEE_Result export_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	bool persistent = false;
	uint32_t *modulus_len = NULL;
	uint32_t *pub_len = NULL;
	unsigned char *modulus = NULL;
	unsigned char *pub_data = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = TEE Key ID, Key security size.
	 * params[1] = Public key buffer.
	 * params[2] = Modulus buffer (RSA key) or none.
	 * params[3] = None.
	 */
	if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(param_types, EXP_PUB_KEY_PARAM_IDX) !=
		    TEE_PARAM_TYPE_MEMREF_OUTPUT ||
	    TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_NONE)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, EXP_MOD_PARAM_IDX) ==
	    TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		modulus = params[EXP_MOD_PARAM_IDX].memref.buffer;
		modulus_len = &params[EXP_MOD_PARAM_IDX].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, EXP_MOD_PARAM_IDX) !=
		   TEE_PARAM_TYPE_NONE) {
		return res;
	}

	res = ta_get_key_handle(&key_handle, params[0].value.a, &persistent);
	if (res) {
		EMSG("Key not found: 0x%x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(key_handle, &obj_info);
	if (res) {
		EMSG("Failed to get object info: 0x%x", res);
		return res;
	}

	pub_data = params[EXP_PUB_KEY_PARAM_IDX].memref.buffer;
	pub_len = &params[EXP_PUB_KEY_PARAM_IDX].memref.size;

	if (obj_info.objectType == TEE_TYPE_RSA_PUBLIC_KEY ||
	    obj_info.objectType == TEE_TYPE_RSA_KEYPAIR)
		res = export_pub_key_rsa(key_handle, modulus, modulus_len,
					 pub_data, pub_len);
	else if (obj_info.objectType == TEE_TYPE_ECDSA_PUBLIC_KEY ||
		 obj_info.objectType == TEE_TYPE_ECDSA_KEYPAIR)
		res = export_pub_key_ecc(key_handle, params[0].value.b,
					 pub_data, pub_len);

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
