// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
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

/* TEE Key type is keypair */
#define TEE_TYPE_KEYPAIR BIT(24)

/*
 * Object ID ranges
 * Object ID ranges can be split between transient and persistent by changing
 * the below ranges definition.
 */
#define OBJECT_ID_TRANSIENT_MIN	 1
#define OBJECT_ID_TRANSIENT_MAX	 UINT32_MAX
#define OBJECT_ID_PERSISTENT_MIN 1
#define OBJECT_ID_PERSISTENT_MAX UINT32_MAX

/**
 * struct obj_data - Object data.
 * @id: Object ID.
 * @handle: Object Handle
 */
struct obj_data {
	uint32_t id;
	TEE_ObjectHandle handle;
};

/**
 * struct obj_list - Transient object list.
 * @data: Object data.
 * @next: Next object of the list.
 */
struct obj_list {
	struct obj_data *data;
	struct obj_list *next;
};

/* Linked list containing transient objects */
static struct obj_list *transient_object_list;

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
 * key_obj_type_to_ta_type() - Get SMW key type of an object type.
 * @key_type: Key type returned.
 * @key_privacy: Key privacy returned.
 * @obj_type: Object type to convert.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- @obj_type is NULL.
 * TEE_ERROR_ITEM_NOT_FOUND	- Key type isn't present.
 */
static TEE_Result key_obj_type_to_ta_type(enum tee_key_type *key_type,
					  enum tee_key_privacy *key_privacy,
					  uint32_t obj_type)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(key_info);

	FMSG("Executing %s", __func__);

	if (!key_type || !key_privacy)
		return TEE_ERROR_BAD_PARAMETERS;

	for (; i < array_size; i++) {
		if ((key_info[i].obj_type & obj_type) == obj_type) {
			*key_type = key_info[i].key_type;

			/*
			 * @obj_type is the TEE retrieved object type, then:
			 *  - If the TEE_TYPE_KEYPAIR is set in @obj_type, it's
			 *    a key pair object.
			 *  - Else if TA defined key_info[i].obj_type is a
			 *    key pair object, then TEE @obj_type is a public
			 *    key object.
			 * Otherwise, it's a private key (symmetric key).
			 */
			if (obj_type & TEE_TYPE_KEYPAIR)
				*key_privacy = TEE_KEY_PAIR;
			else if (key_info[i].obj_type & TEE_KEY_PAIR)
				*key_privacy = TEE_KEY_PUBLIC;
			else
				*key_privacy = TEE_KEY_PRIVATE;

			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

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
 * find_and_open_persistent_id() - Find if object ID is persistent and open it.
 * @id: ID to find.
 * @handle: If not NULL and ID found, return the persistent object handle.
 *
 * Return:
 * TEE_SUCCESS              - @id is present in the persistent storage
 * TEE_ERROR_ITEM_NOT_FOUND - @id is not present in the persistent storage
 * other error              - Unexpected error
 */
static TEE_Result find_and_open_persistent_id(uint32_t id,
					      TEE_ObjectHandle *handle)
{
#define OBJECT_ID_BUFFER_MAX (TEE_OBJECT_ID_MAX_LEN / sizeof(uint32_t) + 1)

	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	TEE_ObjectEnumHandle obj_enum = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	uint32_t *obj_id = NULL;
	size_t obj_id_length = 0;
	bool found = false;

	FMSG("Executing %s", __func__);

	res = TEE_AllocatePersistentObjectEnumerator(&obj_enum);
	if (res == TEE_SUCCESS) {
		obj_id = TEE_Malloc(OBJECT_ID_BUFFER_MAX,
				    TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!obj_id)
			return TEE_ERROR_OUT_OF_MEMORY;

		DMSG("Enumerate all Persistent objects");
		res = TEE_StartPersistentObjectEnumerator(obj_enum,
							  SMW_TEE_STORAGE);

		while (res == TEE_SUCCESS && !found) {
			TEE_MemFill(&obj_info, 0, sizeof(obj_info));
			TEE_MemFill(obj_id, 0, OBJECT_ID_BUFFER_MAX);
			obj_id_length = 0;

			res = TEE_GetNextPersistentObject(obj_enum, &obj_info,
							  obj_id,
							  &obj_id_length);
			if (res == TEE_SUCCESS && obj_id_length == sizeof(id) &&
			    id == obj_id[0])
				found = true;
		}

		TEE_Free(obj_id);
	}

	if (found) {
		DMSG("Persistent object ID 0x%08" PRIx32 " found", id);
		if (handle)
			res = TEE_OpenPersistentObject(SMW_TEE_STORAGE, &id,
						       sizeof(id),
						       PERSISTENT_KEY_FLAGS,
						       handle);
	}

	TEE_FreePersistentObjectEnumerator(obj_enum);

	return res;
}

/**
 * register_persistent_object() - Create and close a persistent object
 * @data: Transient object data
 *
 * Transforms a transient object into a persistent object and close it if
 * success.
 *
 * Return:
 * TEE_SUCCESS              - @id found and deleted
 * other error              - Unexpected error
 */
static TEE_Result register_persistent_object(struct obj_data *data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle handle = TEE_HANDLE_NULL;

	FMSG("Executing %s", __func__);

	res = TEE_CreatePersistentObject(SMW_TEE_STORAGE, &data->id,
					 sizeof(data->id), PERSISTENT_KEY_FLAGS,
					 data->handle, NULL, 0, &handle);

	TEE_CloseObject(handle);

	return res;
}

/**
 * find_and_delete_persistent_id() - Find and delete ID in persistent storage
 * @id: ID to find and delete.
 *
 * Checks if ID is persistent and if found, deletes it.
 *
 * Return:
 * TEE_SUCCESS              - @id found and deleted
 * TEE_ERROR_ITEM_NOT_FOUND - @id not found
 * other error              - Unexpected error
 */
static TEE_Result find_and_delete_persistent_id(uint32_t id)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	TEE_ObjectHandle handle = TEE_HANDLE_NULL;

	FMSG("Executing %s", __func__);

	res = find_and_open_persistent_id(id, &handle);
	if (res == TEE_SUCCESS)
		res = TEE_CloseAndDeletePersistentObject1(handle);

	return res;
}

/**
 * find_and_get_transient_id() - Find if object ID is transient and return
 *                               its handle.
 * @id: ID to find.
 * @handle: If not NULL and ID found, return the transient object handle.
 *
 * Return:
 * TEE_SUCCESS              - @id is present in the transient id list
 * TEE_ERROR_ITEM_NOT_FOUND - @id is not present in the transient id list
 */
static TEE_Result find_and_get_transient_id(uint32_t id,
					    TEE_ObjectHandle *handle)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	struct obj_list *head = transient_object_list;

	FMSG("Executing %s", __func__);

	while (head && res != TEE_SUCCESS) {
		if (head->data->id == id) {
			res = TEE_SUCCESS;
			if (handle)
				*handle = head->data->handle;
		}

		head = head->next;
	}

	return res;
}

/**
 * register_transient_object() - Add transient object in the list
 * @data: Transient object data
 *
 * Create a new key data and push it in the transient object list.
 *
 * Return:
 * TEE_SUCCESS              - Object registered
 * other error              - Unexpected error
 */
static TEE_Result register_transient_object(struct obj_data *data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct obj_data *new_data = NULL;
	struct obj_list *new_obj = NULL;
	struct obj_list *head = NULL;

	FMSG("Executing %s", __func__);

	if (!data) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	new_data =
		TEE_Malloc(sizeof(*new_data), TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!new_data) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	*new_data = *data;

	new_obj = TEE_Malloc(sizeof(*new_obj), TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!new_obj) {
		EMSG("TEE_Malloc failed");
		TEE_Free(new_data);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	new_obj->data = new_data;
	new_obj->next = NULL;

	if (!transient_object_list) {
		/* New key is the first of the list */
		transient_object_list = new_obj;
	} else {
		head = transient_object_list;
		while (head->next)
			head = head->next;
		/* New key is the last of the list */
		head->next = new_obj;
	}

	res = TEE_SUCCESS;
	data->handle = TEE_HANDLE_NULL;

exit:
	return res;
}

/**
 * find_and_delete_transient_id() - Find and delete ID in transient storage
 * @id: ID to find and delete.
 *
 * Checks if ID is transient and if found, deletes it.
 *
 * Return:
 * TEE_SUCCESS              - @id found and deleted
 * TEE_ERROR_ITEM_NOT_FOUND - @id not found
 * other error              - Unexpected error
 */
static TEE_Result find_and_delete_transient_id(uint32_t id)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	struct obj_list *head = NULL;
	struct obj_list *prev = NULL;
	struct obj_list *next = NULL;

	FMSG("Executing %s", __func__);

	if (!id)
		return TEE_ERROR_BAD_PARAMETERS;

	head = transient_object_list;
	prev = transient_object_list;

	while (head && res != TEE_SUCCESS) {
		next = head->next;
		if (head->data->id == id) {
			res = TEE_SUCCESS;

			if (head == transient_object_list)
				transient_object_list = next;
			else
				prev->next = next;

			TEE_FreeTransientObject(head->data->handle);

			TEE_Free(head->data);
			TEE_Free(head);
		}

		prev = head;
		head = next;
	};

	return res;
}

/**
 * is_object_id_used() - Check if an ID is already used.
 * @id: ID to check.
 *
 * Return:
 * TEE_SUCCESS              - @id is already used
 * TEE_ERROR_ITEM_NOT_FOUND - @id is not used
 * other error              - Unexpected error
 */
static TEE_Result is_object_id_used(uint32_t id)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	FMSG("Executing %s", __func__);

	res = find_and_open_persistent_id(id, NULL);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = find_and_get_transient_id(id, NULL);

	return res;
}

/**
 * find_unused_object_id() - Find an unused object ID.
 * @id: [in/out] input object ID to find, return new object ID
 * @persistent: Key storage information.
 *
 * If the @id is 0, finds a free id in the list else checks if the
 * given @id is not used.
 *
 * Return:
 * TEE_SUCCESS                - Success.
 * TEE_ERROR_ITEM_NOT_FOUND   - Failed.
 * TEE_ERROR_BAD_PARAMETERS   - Id already used.
 * TEE_ERROR_STORAGE_NO_SPACE - Not more storage place
 * other error                - Unexpected error.
 */
static TEE_Result find_unused_object_id(uint32_t *id, bool persistent)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	uint32_t i = OBJECT_ID_TRANSIENT_MIN;
	uint32_t max_id = OBJECT_ID_TRANSIENT_MAX;

	FMSG("Executing %s", __func__);

	if (*id) {
		DMSG("Check if ID=0x%08" PRIx32 " is free", *id);
		res = is_object_id_used(*id);
		if (res == TEE_SUCCESS)
			res = TEE_ERROR_BAD_PARAMETERS;
		else if (res == TEE_ERROR_ITEM_NOT_FOUND)
			res = TEE_SUCCESS;

	} else {
		if (persistent) {
			i = OBJECT_ID_PERSISTENT_MIN;
			max_id = OBJECT_ID_PERSISTENT_MAX;
		}
		for (; i < max_id; i++) {
			res = is_object_id_used(i);
			if (res == TEE_SUCCESS)
				continue;

			if (res == TEE_ERROR_ITEM_NOT_FOUND) {
				*id = i;
				DMSG("Found new ID=0x%08" PRIx32, *id);
				res = TEE_SUCCESS;
			}

			break;
		}

		if (i == max_id)
			res = TEE_ERROR_STORAGE_NO_SPACE;
	}

	EMSG("returned 0x%" PRIx32, res);
	return res;
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
 * key_usage_to_tee() - Convert a TA param key usage to TEE key usage
 * @key_usage: Key usage to convert
 * @tee_key_usage: TEE key usage value
 *
 * Return:
 * TEE_SUCCESS                - Success.
 * TEE_ERROR_BAD_PARAMETERS   - Bad key type.
 */
static TEE_Result key_usage_to_tee(unsigned int key_usage,
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
 * key_usage_to_ta() - Convert a TEE key usage to TA param key usage
 * @key_usage: Key usage bit mask result
 * @tee_key_usage: TEE key usage value to convert
 *
 * Return:
 * None.
 */
static void key_usage_to_ta(unsigned int *key_usage, uint32_t tee_key_usage)
{
	unsigned int i;

	FMSG("Executing %s", __func__);

	*key_usage = 0;
	for (i = 0; i < ARRAY_SIZE(conv_key_usage); i++) {
		if (conv_key_usage[i].tee_usage & tee_key_usage)
			*key_usage |= conv_key_usage[i].usage;
	}
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
 * get_ecc_public_key_size() - Get the asymmetric public key size.
 * @handle: Key handle.
 * @size: Public key size retrieved in bytes.
 *
 * Return:
 * TEE_SUCCESS        - Success.
 * TEE_ERROR_GENERIC  - Unexpected success.
 * Error code from TEE_GetObjectBufferAttribute().
 */
static TEE_Result get_ecc_public_key_size(TEE_ObjectHandle handle, size_t *size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t x_size = 0;
	size_t y_size = 0;

	FMSG("Executing %s", __func__);

	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   NULL, &x_size);
	if (res == TEE_ERROR_SHORT_BUFFER)
		res = TEE_GetObjectBufferAttribute(handle,
						   TEE_ATTR_ECC_PUBLIC_VALUE_X,
						   NULL, &y_size);

	if (!res) {
		res = TEE_ERROR_GENERIC;
	} else if (res == TEE_ERROR_SHORT_BUFFER) {
		if (ADD_OVERFLOW(x_size, y_size, size))
			res = TEE_ERROR_GENERIC;
		else
			res = TEE_SUCCESS;
	}

	return res;
}

/**
 * get_rsa_public_key_size() - Get the sizes of RSA public key buffers.
 * @handle: Key handle.
 * @modulus_size: Modulus size retrieved in bytes.
 * @exponent_size: Public exponent size retrieved in bytes.
 *
 * Return:
 * TEE_SUCCESS        - Success.
 * TEE_ERROR_GENERIC  - Unexpected success.
 * Error code from TEE_GetObjectBufferAttribute().
 */
static TEE_Result get_rsa_public_key_size(TEE_ObjectHandle handle,
					  size_t *modulus_size,
					  size_t *exponent_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("Executing %s", __func__);

	/* Get modulus */
	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_RSA_MODULUS, NULL,
					   modulus_size);

	if (res == TEE_ERROR_SHORT_BUFFER)
		/* Get public exponent */
		res = TEE_GetObjectBufferAttribute(handle,
						   TEE_ATTR_RSA_PUBLIC_EXPONENT,
						   NULL, exponent_size);

	if (!res)
		res = TEE_ERROR_GENERIC;
	else if (res == TEE_ERROR_SHORT_BUFFER)
		res = TEE_SUCCESS;

	return res;
}

/**
 * export_pub_key_ecc() - Export asymmetric public key.
 * @handle: Key handle.
 * @pub_key: Pointer to public key buffer.
 * @pub_key_size: Pointer to @pub_key size (bytes).
 *
 * Return:
 * TEE_SUCCESS        - Success.
 * TEE_ERROR_NO_DATA  - @pub_key is not set.
 * TEE_ERROR_GENERIC  - Unexpected success.
 * Error code from TEE_GetObjectBufferAttribute().
 */
static TEE_Result export_pub_key_ecc(TEE_ObjectHandle handle,
				     unsigned char *pub_key,
				     size_t *pub_key_size)
{
	TEE_Result res = TEE_ERROR_NO_DATA;
	size_t x_size = 0;
	size_t y_size = 0;

	FMSG("Executing %s", __func__);

	if (!pub_key)
		return res;

	res = get_ecc_public_key_size(handle, &x_size);
	if (res)
		return res;

	if (*pub_key_size < x_size) {
		*pub_key_size = x_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	*pub_key_size = x_size;
	/* Get first part of public key */
	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   pub_key, &x_size);
	if (!res) {
		/* Get second part of the public key */
		y_size = *pub_key_size - x_size;

		res = TEE_GetObjectBufferAttribute(handle,
						   TEE_ATTR_ECC_PUBLIC_VALUE_Y,
						   pub_key + x_size, &y_size);
	}

	if (res)
		EMSG("TEE_GetObjectBufferAttribute returned 0x%x", res);

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
 * TEE_SUCCESS        - Success.
 * TEE_ERROR_NO_DATA  - @modulus and @pub_exp are not set.
 * TEE_ERROR_GENERIC  - Unexpected success.
 * Error code from TEE_GetObjectBufferAttribute().
 */
static TEE_Result export_pub_key_rsa(TEE_ObjectHandle handle,
				     unsigned char *modulus,
				     size_t *modulus_len,
				     unsigned char *pub_exp,
				     size_t *pub_exp_len)
{
	TEE_Result res = TEE_ERROR_NO_DATA;
	size_t mod_size = 0;
	size_t exp_size = 0;

	FMSG("Executing %s", __func__);

	if (!(modulus && pub_exp))
		return res;

	res = get_rsa_public_key_size(handle, &mod_size, &exp_size);
	if (res)
		return res;

	if (*modulus_len < mod_size || *pub_exp_len < exp_size) {
		*modulus_len = mod_size;
		*pub_exp_len = exp_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Get modulus */
	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_RSA_MODULUS,
					   modulus, modulus_len);
	if (!res)
		/* Get public exponent */
		res = TEE_GetObjectBufferAttribute(handle,
						   TEE_ATTR_RSA_PUBLIC_EXPONENT,
						   pub_exp, pub_exp_len);

	if (res)
		EMSG("TEE_GetObjectBufferAttribute returned 0x%x", res);

	return res;
}

TEE_Result generate_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_Attribute key_attr = { 0 };
	uint32_t object_type = 0;
	uint32_t attr_count = 0;
	unsigned int security_size = 0;
	unsigned char *pub_key = NULL;
	unsigned char *modulus = NULL;
	unsigned char *rsa_pub_exp_attr = NULL;
	size_t *pub_key_size = NULL;
	size_t *modulus_size = NULL;
	size_t rsa_pub_exp_attr_len = 0;
	bool persistent = false;
	struct obj_data obj_data = { 0 };
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

	/* Find a new ID or if user ID is free */
	obj_data.id = shared_params->id;
	res = find_unused_object_id(&obj_data.id, persistent);
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

	res = key_usage_to_tee(shared_params->key_usage, &key_usage);
	if (res) {
		EMSG("Key usage 0x%08X is not valid", shared_params->key_usage);
		return res;
	}

	/* Allocate a transient object */
	res = TEE_AllocateTransientObject(object_type, security_size,
					  &obj_data.handle);
	if (res) {
		EMSG("Failed to allocate transient object: 0x%x", res);
		return res;
	}

	/* Generate key */
	res = TEE_GenerateKey(obj_data.handle, security_size, &key_attr,
			      attr_count);
	if (res) {
		EMSG("Failed to generate key: 0x%x", res);
		goto err;
	}

	/* Set key usage. Make it non extractable */
	res = set_key_usage(key_usage, obj_data.handle);
	if (res) {
		EMSG("Failed to set key usage: 0x%x", res);
		goto err;
	}

	if (key_type == TEE_KEY_TYPE_ID_RSA)
		/* Export RSA public key */
		res = export_pub_key_rsa(obj_data.handle, modulus, modulus_size,
					 pub_key, pub_key_size);
	else if (key_type == TEE_KEY_TYPE_ID_ECDSA)
		/* Export ECDSA public key */
		res = export_pub_key_ecc(obj_data.handle, pub_key,
					 pub_key_size);

	if (res != TEE_SUCCESS && res != TEE_ERROR_NO_DATA) {
		EMSG("Failed to export public key: 0x%x", res);
		goto err;
	}

	if (persistent)
		res = register_persistent_object(&obj_data);
	else
		res = register_transient_object(&obj_data);

	/* Share key ID with Normal World in case of operation success */
	if (res == TEE_SUCCESS)
		shared_params->id = obj_data.id;

err:
	TEE_FreeTransientObject(obj_data.handle);

	return res;
}

TEE_Result delete_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t exp_param_types = 0;

	FMSG("Executing %s", __func__);

	/* params[0] = Key ID */
	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return res;

	if (params[0].value.a) {
		res = find_and_delete_persistent_id(params[0].value.a);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			res = find_and_delete_transient_id(params[0].value.a);
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
	unsigned int security_size = 0;
	unsigned int priv_key_len = 0;
	unsigned int pub_key_len = 0;
	unsigned int modulus_len = 0;
	unsigned char *priv_key = NULL;
	unsigned char *pub_key = NULL;
	unsigned char *modulus = NULL;
	bool persistent = false;
	struct obj_data obj_data = { 0 };
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

	/* Find a new ID or if user ID is free */
	obj_data.id = shared_params->id;
	res = find_unused_object_id(&obj_data.id, persistent);
	if (res)
		return res;

	res = key_usage_to_tee(shared_params->key_usage, &key_usage);
	if (res) {
		EMSG("Key usage 0x%08X is not valid", shared_params->key_usage);
		return res;
	}

	res = ta_import_key(&obj_data.handle, key_type, security_size,
			    key_usage, priv_key, priv_key_len, pub_key,
			    pub_key_len, modulus, modulus_len);
	if (res) {
		EMSG("Failed to import key: 0x%x", res);
		goto exit;
	}

	if (persistent)
		res = register_persistent_object(&obj_data);
	else
		res = register_transient_object(&obj_data);

	/* Share key ID with Normal World in case of operation success */
	if (res == TEE_SUCCESS)
		shared_params->id = obj_data.id;

exit:
	TEE_FreeTransientObject(obj_data.handle);

	return res;
}

TEE_Result ta_get_key_handle(TEE_ObjectHandle *key_handle, uint32_t key_id,
			     bool *persistent)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	if (!key_handle || !persistent || !key_id)
		return res;

	*persistent = false;

	res = find_and_open_persistent_id(key_id, key_handle);
	if (res == TEE_SUCCESS)
		*persistent = true;
	else if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = find_and_get_transient_id(key_id, key_handle);

	return res;
}

TEE_Result export_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	bool persistent = false;
	size_t *modulus_len = NULL;
	size_t *pub_len = NULL;
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
		goto exit;
	}

	pub_data = params[EXP_PUB_KEY_PARAM_IDX].memref.buffer;
	pub_len = &params[EXP_PUB_KEY_PARAM_IDX].memref.size;

	if (obj_info.objectType == TEE_TYPE_RSA_PUBLIC_KEY ||
	    obj_info.objectType == TEE_TYPE_RSA_KEYPAIR)
		res = export_pub_key_rsa(key_handle, modulus, modulus_len,
					 pub_data, pub_len);
	else if (obj_info.objectType == TEE_TYPE_ECDSA_PUBLIC_KEY ||
		 obj_info.objectType == TEE_TYPE_ECDSA_KEYPAIR)
		res = export_pub_key_ecc(key_handle, pub_data, pub_len);

exit:
	if (persistent)
		TEE_CloseObject(key_handle);

	return res;
}

TEE_Result clear_key_linked_list(void)
{
	TEE_Result res = TEE_SUCCESS;
	struct obj_list *head = transient_object_list;
	struct obj_list *next = NULL;

	FMSG("Executing %s", __func__);

	while (head) {
		next = head->next;
		res = find_and_delete_transient_id(head->data->id);
		if (res) {
			EMSG("Can't delete key from linked list: 0x%x", res);
			break;
		}

		head = next;
	}

	return res;
}

TEE_Result get_key_lengths(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	bool persistent = false;
	size_t public_length = 0;
	size_t modulus_length = 0;
	enum tee_key_type smw_key_type = TEE_KEY_TYPE_ID_INVALID;
	enum tee_key_privacy key_privacy = TEE_KEY_PUBLIC;

	FMSG("Executing %s", __func__);

	/*
	 * params[0].value.a = TEE Key ID.
	 * params[0].value.b = TEE Key type returned.
	 * params[1].value.a = Public key buffer length.
	 * params[1].value.b = Modulus buffer (RSA key) length.
	 * params[2].value.a = Private key buffer length.
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
					   TEE_PARAM_TYPE_VALUE_OUTPUT,
					   TEE_PARAM_TYPE_VALUE_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return res;

	res = ta_get_key_handle(&key_handle,
				params[GET_KEY_LENGTHS_KEY_ID_IDX].value.a,
				&persistent);
	if (res) {
		EMSG("Key not found: 0x%x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(key_handle, &obj_info);
	if (res) {
		EMSG("Failed to get object info: 0x%x", res);
		goto exit;
	}

	res = key_obj_type_to_ta_type(&smw_key_type, &key_privacy,
				      obj_info.objectType);
	if (res) {
		EMSG("Key type (0x%08x) not found 0x%x", obj_info.objectType,
		     res);
		goto exit;
	}

	params[GET_KEY_LENGTHS_KEY_ID_IDX].value.b = smw_key_type;

	switch (obj_info.objectType) {
	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_RSA_KEYPAIR:
		res = get_rsa_public_key_size(key_handle, &modulus_length,
					      &public_length);
		break;

	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_KEYPAIR:
		res = get_ecc_public_key_size(key_handle, &public_length);
		break;

	default:
		res = TEE_SUCCESS;
		break;
	}

	params[GET_KEY_LENGTHS_PUBKEYS_IDX].value.a = public_length;
	params[GET_KEY_LENGTHS_PUBKEYS_IDX].value.b = modulus_length;

	/* Private key is protected, hence length can't retrieved */
	params[GET_KEY_LENGTHS_PRIVKEY_IDX].value.a = 0;

exit:
	if (persistent)
		TEE_CloseObject(key_handle);

	return res;
}

TEE_Result get_key_attributes(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	bool persistent = false;
	enum tee_key_type key_type = TEE_KEY_TYPE_ID_INVALID;
	enum tee_key_privacy key_privacy = TEE_KEY_PUBLIC;
	unsigned int key_usage = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0].value.a = TEE Key ID.
	 * params[1].value.a = TEE Key type returned.
	 * params[1].value.b = TEE Key usage returned.
	 * params[2].value.a = TEE Key keypair (1) /public (0) flag returned.
	 * params[2].value.b = TEE Key persistent flag returned.
	 * params[3].value.a = TEE Key size returned.
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_VALUE_OUTPUT,
					   TEE_PARAM_TYPE_VALUE_OUTPUT,
					   TEE_PARAM_TYPE_VALUE_OUTPUT))
		return res;

	res = ta_get_key_handle(&key_handle,
				params[GET_KEY_ATTRS_KEY_ID_IDX].value.a,
				&persistent);
	if (res) {
		EMSG("Key not found: 0x%x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(key_handle, &obj_info);
	if (res) {
		EMSG("Failed to get object info: 0x%x", res);
		goto exit;
	}

	res = key_obj_type_to_ta_type(&key_type, &key_privacy,
				      obj_info.objectType);
	if (res) {
		EMSG("Key type (0x%08x) not found 0x%x", obj_info.objectType,
		     res);
		goto exit;
	}

	key_usage_to_ta(&key_usage, obj_info.objectUsage);

	params[GET_KEY_ATTRS_KEY_TYPE_IDX].value.a = key_type;
	params[GET_KEY_ATTRS_KEY_USAGE_IDX].value.b = key_usage;
	params[GET_KEY_ATTRS_KEYPAIR_FLAG_IDX].value.a = key_privacy;
	params[GET_KEY_ATTRS_PERSISTENT_FLAG_IDX].value.b = persistent;
	params[GET_KEY_ATTRS_KEY_SIZE_IDX].value.a = obj_info.objectSize;

exit:
	if (persistent)
		TEE_CloseObject(key_handle);

	return res;
}
