// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdlib.h>
#include <util.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "common.h"
#include "tee_subsystem.h"
#include "obj.h"
#include "keymgr_derive.h"

/* Number of attributes */
#define NB_ATTR_HKDF 3
#define NB_ATTR_ECDH 4

#define INVALID_KEY_ID		0
#define MAX_KEY_SIZE_GEN_SECRET 2048

#define SECURITY_SIZE_RANGE INT_MAX

static void set_attr_buffer(size_t attr_count, TEE_Attribute *attrs,
			    uint32_t attr_id, const void *buf, size_t len)

{
	attrs[attr_count].attributeID = attr_id;
	attrs[attr_count].content.ref.buffer = (void *)buf;
	attrs[attr_count].content.ref.length = len;
}

static void set_attr_value(size_t attr_count, TEE_Attribute *attrs,
			   uint32_t attr_id, uint32_t value_a, uint32_t value_b)

{
	attrs[attr_count].attributeID = attr_id;
	attrs[attr_count].content.value.a = value_a;
	attrs[attr_count].content.value.b = value_b;
}

/**
 * set_derive_key_attr() - Set key derivation attributes.
 * @shared_params: Pointer to derive key shared parameters.
 * @ta_param: Shared parameter between secure and normal world.
 * @key_attr: Pointer to TEE attribute structure to fill.
 * @attr_count: Total attribute count.
 * @derived_key_len: Length of the derived key.
 *
 * Return:
 * TEE_SUCCESS              - Success.
 * TEE_ERROR_BAD_PARAMETERS - One of the parameters is invalid.
 */
static TEE_Result
set_derive_key_attr(struct key_derive_shared_params *shared_params,
		    TEE_Param ta_param, TEE_Attribute *key_attr,
		    uint32_t *attr_count, size_t derived_key_len)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	unsigned char *salt = NULL;
	unsigned char *info = NULL;
	unsigned char *public_key = NULL;
	uint32_t key_len = 0;
	uint32_t base_key_len = 0;
	size_t public_key_len = 0;

	switch (shared_params->derive_algo) {
	case TEE_ALG_HKDF_MD5_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA1_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA224_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA256_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA384_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA512_DERIVE_KEY:
		salt = ta_param.memref.buffer;
		if (shared_params->salt_length) {
			set_attr_buffer(*attr_count, key_attr,
					TEE_ATTR_HKDF_SALT, salt,
					shared_params->salt_length);

			if (ADD_OVERFLOW(*attr_count, 1, attr_count))
				return res;
		}

		if (shared_params->info_length) {
			info = salt + shared_params->salt_length;
			set_attr_buffer(*attr_count, key_attr,
					TEE_ATTR_HKDF_INFO, info,
					shared_params->info_length);

			if (ADD_OVERFLOW(*attr_count, 1, attr_count))
				return res;
		}

		if (ADD_OVERFLOW(derived_key_len, 0, &key_len))
			return res;

		set_attr_value(*attr_count, key_attr, TEE_ATTR_HKDF_OKM_LENGTH,
			       key_len, 0);

		if (ADD_OVERFLOW(*attr_count, 1, attr_count))
			return res;

		break;

	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		public_key = ta_param.memref.buffer;
		public_key_len = ta_param.memref.size;
		base_key_len =
			BITS_TO_BYTES_SIZE(shared_params->base_key_sec_size);
		if (public_key_len < base_key_len * 2)
			return TEE_ERROR_SHORT_BUFFER;

		set_attr_buffer(*attr_count, key_attr,
				TEE_ATTR_ECC_PUBLIC_VALUE_X, public_key,
				base_key_len);

		if (ADD_OVERFLOW(*attr_count, 1, attr_count))
			return TEE_ERROR_OVERFLOW;

		public_key += base_key_len;

		set_attr_buffer(*attr_count, key_attr,
				TEE_ATTR_ECC_PUBLIC_VALUE_Y, public_key,
				base_key_len);

		if (ADD_OVERFLOW(*attr_count, 1, attr_count))
			return TEE_ERROR_OVERFLOW;

		break;

	default:
		return res;
	}

	return TEE_SUCCESS;
}

/**
 * get_secret_key_length() - Get key length.
 * @handle: Key object handle.
 * @key_buf_len: Pointer to hold the length of the derived key.
 *
 * Return:
 * TEE_SUCCESS                     - Success.
 * TEE_ERROR_ITEM_NOT_FOUND        - Attribute is not found on this object
 * TEE_ERROR_CORRUPT_OBJECT        - Persistent object is corrupt.
 * TEE_ERROR_STORAGE_NOT_AVAILABLE - Persistent object is stored in a storage
 *                                   area which is currently inaccessible.
 */
static TEE_Result get_secret_key_length(TEE_ObjectHandle handle,
					size_t *key_buf_len)
{
	TEE_Result res = TEE_SUCCESS;

	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_SECRET_VALUE, NULL,
					   key_buf_len);
	if (res != TEE_ERROR_SHORT_BUFFER)
		return res;

	res = TEE_SUCCESS;
	return res;
}

/**
 * get_obj_buffer_attr() - Retrieve attribute from an object.
 * @handle: Object handle.
 * @key_buf: Output buffer to get the content of the attribute.
 * @key_buf_len: key_buf length.
 * @create_buffer: True, if buffer needs to be allocated.
 *
 * This function retrieves the attribute "TEE_ATTR_SECRET_VALUE" from secret key
 * object. Additionally, allocates the memory to hold the attribute buffer,
 * if @create_buffer is set to true.
 *
 * Return:
 * TEE_SUCCESS                     - Success.
 * TEE_ERROR_ITEM_NOT_FOUND        - Attribute is not found on this object
 * TEE_ERROR_CORRUPT_OBJECT        - Persistent object is corrupt.
 * TEE_ERROR_STORAGE_NOT_AVAILABLE - Persistent object is stored in a storage
 *                                   area which is currently inaccessible.
 */
static TEE_Result get_obj_buffer_attr(TEE_ObjectHandle handle,
				      unsigned char **key_buf,
				      size_t *key_buf_len, bool create_buffer)
{
	TEE_Result res = TEE_SUCCESS;

	res = get_secret_key_length(handle, key_buf_len);
	if (res != TEE_SUCCESS)
		return res;

	if (create_buffer) {
		*key_buf = TEE_Malloc(*key_buf_len, TEE_MALLOC_FILL_ZERO);
		if (!*key_buf) {
			EMSG("Allocation error");
			res = TEE_ERROR_OUT_OF_MEMORY;
			return res;
		}
	}

	res = TEE_GetObjectBufferAttribute(handle, TEE_ATTR_SECRET_VALUE,
					   *key_buf, key_buf_len);
	if (res)
		EMSG("TEE_GetObjectBufferAttribute returned 0x%x", res);

	return res;
}

/**
 * is_derive_usage_set() - Check if derive usage is set for key.
 * @key_id: Key ID.
 * @handle: Key handle.
 * @op_handle: Operation handle.
 *
 * Return:
 * TEE_SUCCESS                - Success.
 * Error code from TEE_GetObjectInfo1().
 * Error code from check_operation_keys_usage().
 */
static TEE_Result is_derive_usage_set(uint32_t key_id, TEE_ObjectHandle handle,
				      TEE_OperationHandle op_handle)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectInfo key_info = { 0 };

	FMSG("Executing %s", __func__);

	/* If key already exists, check if "derive" usage is set */
	if (key_id) {
		/* Get key info */
		res = TEE_GetObjectInfo1(handle, &key_info);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get key info (0x%x)", res);
			return res;
		}

		res = check_operation_keys_usage(op_handle, &key_info, 1);
	}

	return res;
}

static TEE_Result
import_derived_key(struct key_derive_shared_params *shared_params,
		   struct obj_data *derived_key_object,
		   unsigned char *shared_secret, unsigned int shared_secret_len)
{
	uint32_t key_usage = 0;
	TEE_Result res = TEE_SUCCESS;

	/* Convert SMW key usage to TEE key usage */
	res = key_usage_to_tee(shared_params->key_usage, &key_usage);
	if (res)
		goto exit;

	/* Find a new ID for derived key */
	res = ta_find_unused_object_id(&derived_key_object->id,
				       shared_params->persistent);
	if (res)
		goto exit;

	res = ta_import_key(&derived_key_object->handle,
			    shared_params->key_type,
			    shared_params->derived_key_sec_size, key_usage,
			    shared_secret, shared_secret_len, NULL, 0, NULL, 0);
	if (res) {
		EMSG("Failed to import key: 0x%x", res);
		goto exit;
	}

	if (shared_params->persistent)
		res = ta_register_persistent_object(derived_key_object);
	else
		res = ta_register_transient_object(derived_key_object);

	/* Share key ID with Normal World in case of operation success */
	if (res == TEE_SUCCESS)
		shared_params->derived_key_id = derived_key_object->id;

exit:
	return res;
}

static TEE_Result hkdf_derive_key(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle base_key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr[NB_ATTR_HKDF] = { 0 };

	struct key_derive_shared_params *shared_params = NULL;
	struct key_handle imported_key_handle = { 0 };
	struct obj_data derived_key_obj = { 0 };
	struct obj_data new_key_object = { 0 };

	size_t base_key_len = 0;
	size_t derived_key_len = 0;
	unsigned int key_len = 0;
	unsigned char *base_key = NULL;
	unsigned char *derived_key = NULL;
	bool mem_allocated_to_der_key = false;

	/* Max key size in bits */
	uint32_t max_key_size = 0;
	uint32_t attr_count = 0;
	bool base_key_exists = false;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Pointer to derive key shared params structure.
	 * params[1] = Pointer to base key buffer or none.
	 * params[2] = Pointer to derived key buffer or none.
	 * params[3] = Salt/info or none.
	 */
	if ((TEE_PARAM_TYPE_GET(param_types, DER_SHARED_PARAM_IDX) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[DER_SHARED_PARAM_IDX].memref.size !=
		    sizeof(*shared_params) ||
	    !params[DER_SHARED_PARAM_IDX].memref.buffer)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, DER_BASE_KEY_PARAM_IDX) !=
	    TEE_PARAM_TYPE_MEMREF_INPUT)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, DER_DERIVED_KEY_PARAM_IDX) !=
	    TEE_PARAM_TYPE_MEMREF_OUTPUT)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, DER_SHARED_MEM_IDX) !=
		    TEE_PARAM_TYPE_MEMREF_INPUT &&
	    TEE_PARAM_TYPE_GET(param_types, DER_SHARED_MEM_IDX) !=
		    TEE_PARAM_TYPE_NONE)
		return res;

	shared_params = params[DER_SHARED_PARAM_IDX].memref.buffer;

	base_key = params[DER_BASE_KEY_PARAM_IDX].memref.buffer;
	derived_key = params[DER_DERIVED_KEY_PARAM_IDX].memref.buffer;

	base_key_len = params[DER_BASE_KEY_PARAM_IDX].memref.size;
	derived_key_len = params[DER_DERIVED_KEY_PARAM_IDX].memref.size;

	/*
	 * Get Base key handle
	 * 1. If base key already exists in TEE, get the key handle.
	 * 2. If base key buffer is set, import the key first and get the key handle.
	 */
	if (shared_params->base_key_id && !base_key) {
		base_key_exists = true;
		res = ta_get_obj_handle(&imported_key_handle.handle,
					shared_params->base_key_id,
					&imported_key_handle.persistent);
		if (res != TEE_SUCCESS)
			goto exit;

		base_key_handle = imported_key_handle.handle;

	} else if ((shared_params->base_key_id == INVALID_KEY_ID) && base_key) {
		if (MUL_OVERFLOW(base_key_len, 8, &max_key_size))
			goto exit;

		res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM,
						  max_key_size,
						  &base_key_handle);
		if (res) {
			EMSG("Failed to allocate transient object: 0x%x", res);
			goto exit;
		}

		set_attr_buffer(attr_count, key_attr, TEE_ATTR_HKDF_IKM,
				base_key, base_key_len);

		res = TEE_PopulateTransientObject(base_key_handle, key_attr, 1);
		if (res) {
			EMSG("Failed to populate transient object: 0x%x", res);
			goto exit;
		}
	} else {
		goto exit;
	}

	/* Allocate operation */
	res = TEE_AllocateOperation(&op_handle, shared_params->derive_algo,
				    TEE_MODE_DERIVE, MAX_KEY_SIZE_GEN_SECRET);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation (0x%x)", res);
		goto exit;
	}

	/* Check if "derive" usage is set for base key */
	res = is_derive_usage_set(shared_params->base_key_id, base_key_handle,
				  op_handle);
	if (res)
		goto exit;

	/* Associate base key with operation */
	res = TEE_SetOperationKey(op_handle, base_key_handle);
	if (res) {
		EMSG("Failed to set operation key: 0x%x", res);
		goto exit;
	}

	/* Allocate a shared secret output object */
	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					  shared_params->derived_key_sec_size,
					  &derived_key_obj.handle);
	if (res) {
		EMSG("Failed to allocate shared secret output object: 0x%x",
		     res);
		goto exit;
	}

	if (!derived_key_len)
		derived_key_len =
			BITS_TO_BYTES_SIZE(shared_params->derived_key_sec_size);

	/* Set HKDF operation parameters */
	res = set_derive_key_attr(shared_params, params[DER_SHARED_MEM_IDX],
				  key_attr, &attr_count, derived_key_len);
	if (res) {
		EMSG("Failed to set derive key attributes: 0x%x", res);
		goto exit;
	}

	TEE_DeriveKey(op_handle, key_attr, attr_count, derived_key_obj.handle);

	/*
	 * If shared secret buffer and length are set, export shared secret buffer.
	 * If the user has requested to store the derived key and shared secret
	 * buffer is not set, allocate memory to store the shared secret
	 * and free it after the operation.
	 */
	if (!derived_key) {
		if (shared_params->store_derived_key) {
			mem_allocated_to_der_key = true;
			res = get_obj_buffer_attr(derived_key_obj.handle,
						  &derived_key,
						  &derived_key_len, true);
		} else {
			res = get_secret_key_length(derived_key_obj.handle,
						    &derived_key_len);
		}

	} else {
		res = get_obj_buffer_attr(derived_key_obj.handle, &derived_key,
					  &derived_key_len, false);
	}

	if (res)
		goto exit;

	params[DER_DERIVED_KEY_PARAM_IDX].memref.size = derived_key_len;

	if (ADD_OVERFLOW(derived_key_len, 0, &key_len)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* If user has requested to store the derived key,
	 * derived key buffer will be imported and user defined key type will be
	 * set and the ID would be returned.
	 */
	if (shared_params->store_derived_key) {
		res = import_derived_key(shared_params, &new_key_object,
					 derived_key, key_len);
		if (res)
			goto exit;
	}

exit:
	TEE_FreeOperation(op_handle);

	if (!base_key_exists)
		TEE_FreeTransientObject(base_key_handle);

	TEE_FreeTransientObject(derived_key_obj.handle);

	TEE_FreeTransientObject(new_key_object.handle);

	if (imported_key_handle.persistent)
		TEE_CloseObject(imported_key_handle.handle);

	if (mem_allocated_to_der_key)
		TEE_Free(derived_key);

	FMSG("%s returned %d\n", __func__, res);

	return res;
}

static bool is_hkdf_algo(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_HKDF_MD5_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA1_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA224_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA256_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA384_DERIVE_KEY:
	case TEE_ALG_HKDF_SHA512_DERIVE_KEY:
		return true;

	default:
		return false;
	}
}

static TEE_Result alloc_get_tee_attribute_data(TEE_ObjectHandle key_handle,
					       uint32_t attribute,
					       unsigned char **data,
					       size_t *size)
{
	TEE_Result res = TEE_SUCCESS;
	void *ptr = NULL;
	size_t sz = 0;

	res = TEE_GetObjectBufferAttribute(key_handle, attribute, NULL, &sz);
	if (res != TEE_ERROR_SHORT_BUFFER)
		return res;

	if (!sz)
		return TEE_ERROR_NO_DATA;

	ptr = TEE_Malloc(sz, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!ptr)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_GetObjectBufferAttribute(key_handle, attribute, ptr, &sz);
	if (res) {
		TEE_Free(ptr);
	} else {
		*data = ptr;
		*size = sz;
	}

	return res;
}

static TEE_Result ecdh_import_key(TEE_ObjectHandle *key_handle,
				  unsigned int security_size,
				  unsigned char *private_key,
				  size_t private_key_len,
				  unsigned char *public_x, size_t public_x_len,
				  unsigned char *public_y, size_t public_y_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute key_attr[NB_ATTR_ECDH] = { 0 };

	uint32_t attr_count = 0;
	unsigned int ecc_curve = 0;

	res = get_key_ecc_curve(TEE_KEY_TYPE_ID_SECP_R1, security_size,
				&ecc_curve);
	if (res)
		return res;

	set_attr_value(attr_count, key_attr, TEE_ATTR_ECC_CURVE, ecc_curve, 0);
	if (ADD_OVERFLOW(attr_count, 1, &attr_count))
		return TEE_ERROR_OVERFLOW;

	set_attr_buffer(attr_count, key_attr, TEE_ATTR_ECC_PRIVATE_VALUE,
			private_key, private_key_len);
	if (ADD_OVERFLOW(attr_count, 1, &attr_count))
		return TEE_ERROR_OVERFLOW;

	set_attr_buffer(attr_count, key_attr, TEE_ATTR_ECC_PUBLIC_VALUE_X,
			public_x, public_x_len);
	if (ADD_OVERFLOW(attr_count, 1, &attr_count))
		return TEE_ERROR_OVERFLOW;

	set_attr_buffer(attr_count, key_attr, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			public_y, public_y_len);
	if (ADD_OVERFLOW(attr_count, 1, &attr_count))
		return TEE_ERROR_OVERFLOW;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, security_size,
					  key_handle);
	if (res)
		return res;

	res = TEE_PopulateTransientObject(*key_handle, key_attr, attr_count);
	if (res)
		goto exit;

	return TEE_SUCCESS;

exit:
	TEE_FreeTransientObject(*key_handle);

	return res;
}

static TEE_Result import_base_key(TEE_ObjectHandle *key_handle,
				  unsigned int security_size,
				  unsigned char *base_key,
				  unsigned int base_key_len)
{
	size_t key_len = 0;
	unsigned char *private_key = NULL;
	unsigned char *public_x = NULL;
	unsigned char *public_y = NULL;

	key_len = BITS_TO_BYTES_SIZE(security_size);

	if (base_key_len < key_len * 3)
		return TEE_ERROR_SHORT_BUFFER;

	public_x = base_key;
	public_y = public_x + key_len;
	private_key = public_y + key_len;

	return ecdh_import_key(key_handle, security_size, private_key, key_len,
			       public_x, key_len, public_y, key_len);
}

static TEE_Result ecdh_derive_key(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle base_key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle ecdh_key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr[NB_ATTR_ECDH] = { 0 };
	TEE_ObjectInfo base_key_info = { 0 };

	struct key_derive_shared_params *shared_params = NULL;
	struct key_handle imported_key_handle = { 0 };
	struct obj_data derived_key_obj = { 0 };
	struct obj_data new_key_object = { 0 };

	size_t private_key_len = 0;
	size_t public_x_len = 0;
	size_t public_y_len = 0;
	size_t base_key_len = 0;
	size_t derived_key_len = 0;
	unsigned int key_len = 0;
	unsigned char *base_key = NULL;
	unsigned char *derived_key = NULL;
	unsigned char *private_key = NULL;
	unsigned char *public_x = NULL;
	unsigned char *public_y = NULL;
	bool mem_allocated_to_der_key = false;
	bool base_key_exists = false;

	uint32_t attr_count = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Pointer to derive key shared params structure.
	 * params[1] = Pointer to derived key buffer.
	 */
	if ((TEE_PARAM_TYPE_GET(param_types, DER_SHARED_PARAM_IDX) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[0].memref.size != sizeof(*shared_params) ||
	    !params[0].memref.buffer)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, DER_DERIVED_KEY_PARAM_IDX) !=
	    TEE_PARAM_TYPE_MEMREF_OUTPUT)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, DER_SHARED_MEM_IDX) !=
	    TEE_PARAM_TYPE_MEMREF_INPUT)
		return res;

	shared_params = params[DER_SHARED_PARAM_IDX].memref.buffer;

	base_key = params[DER_BASE_KEY_PARAM_IDX].memref.buffer;
	derived_key = params[DER_DERIVED_KEY_PARAM_IDX].memref.buffer;

	base_key_len = params[DER_BASE_KEY_PARAM_IDX].memref.size;
	derived_key_len = params[DER_DERIVED_KEY_PARAM_IDX].memref.size;

	/*
	 * Get Base key handle
	 */
	if (shared_params->base_key_id) {
		base_key_exists = true;
		res = ta_get_obj_handle(&imported_key_handle.handle,
					shared_params->base_key_id,
					&imported_key_handle.persistent);
		if (res != TEE_SUCCESS)
			goto exit;

		base_key_handle = imported_key_handle.handle;
	} else if ((shared_params->base_key_id == INVALID_KEY_ID) && base_key) {
		res = import_base_key(&ecdh_key_handle,
				      shared_params->base_key_sec_size,
				      base_key, base_key_len);
		if (res != TEE_SUCCESS)
			goto exit;
	} else {
		goto exit;
	}

	/* Allocate operation */
	res = TEE_AllocateOperation(&op_handle, shared_params->derive_algo,
				    TEE_MODE_DERIVE,
				    shared_params->base_key_sec_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation (0x%x)", res);
		goto exit;
	}

	if (base_key_exists) {
		/*
		 * Check that TEE_USAGE_EXTRACTABLE is set.
		 */
		res = TEE_GetObjectInfo1(base_key_handle, &base_key_info);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get key information (0x%x)", res);
			goto exit;
		}

		if (!(base_key_info.objectUsage & TEE_USAGE_EXTRACTABLE)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto exit;
		}

		/*
		 * TEE EC key derivation could be done on the TEE_TYPE_ECDH_KEYPAIR
		 * key type only. We must extract the ECDSA key attribute to create
		 * a temporary TEE_TYPE_ECDH_KEYPAIR.
		 */
		res = alloc_get_tee_attribute_data(base_key_handle,
						   TEE_ATTR_ECC_PRIVATE_VALUE,
						   &private_key,
						   &private_key_len);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get key attribute (0x%x)", res);
			goto exit;
		}

		res = alloc_get_tee_attribute_data(base_key_handle,
						   TEE_ATTR_ECC_PUBLIC_VALUE_X,
						   &public_x, &public_x_len);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get key attribute (0x%x)", res);
			goto exit;
		}

		res = alloc_get_tee_attribute_data(base_key_handle,
						   TEE_ATTR_ECC_PUBLIC_VALUE_Y,
						   &public_y, &public_y_len);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get key attribute (0x%x)", res);
			goto exit;
		}

		res = ecdh_import_key(&ecdh_key_handle,
				      shared_params->base_key_sec_size,
				      private_key, private_key_len, public_x,
				      public_x_len, public_y, public_y_len);
		if (res)
			goto exit;
	}

	/* Associate base key with operation */
	res = TEE_SetOperationKey(op_handle, ecdh_key_handle);
	if (res) {
		EMSG("Failed to set operation key: 0x%x", res);
		goto exit;
	}

	/* Allocate a shared secret output object */
	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					  shared_params->derived_key_sec_size,
					  &derived_key_obj.handle);
	if (res) {
		EMSG("Failed to allocate shared secret output object: 0x%x",
		     res);
		goto exit;
	}

	attr_count = 0;

	if (!derived_key_len)
		derived_key_len =
			BITS_TO_BYTES_SIZE(shared_params->derived_key_sec_size);

	/* Set ECDH operation parameters */
	res = set_derive_key_attr(shared_params, params[DER_SHARED_MEM_IDX],
				  key_attr, &attr_count, derived_key_len);
	if (res) {
		EMSG("Failed to set derive key attributes: 0x%x", res);
		goto exit;
	}

	TEE_DeriveKey(op_handle, key_attr, attr_count, derived_key_obj.handle);

	/*
	 * If shared secret buffer and length are set, export shared secret buffer.
	 * If the user has requested to store the derived key and shared secret
	 * buffer is not set, allocate memory to store the shared secret
	 * and free it after the operation.
	 */

	if (!derived_key) {
		if (shared_params->store_derived_key) {
			mem_allocated_to_der_key = true;
			res = get_obj_buffer_attr(derived_key_obj.handle,
						  &derived_key,
						  &derived_key_len, true);
		} else {
			res = get_secret_key_length(derived_key_obj.handle,
						    &derived_key_len);
		}
	} else {
		res = get_obj_buffer_attr(derived_key_obj.handle, &derived_key,
					  &derived_key_len, false);
	}

	if (res)
		goto exit;

	params[1].memref.size = derived_key_len;

	if (ADD_OVERFLOW(derived_key_len, 0, &key_len)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* If user has requested to store the derived key,
	 * derived key buffer will be imported and user defined key type will be
	 * set and the ID would be returned.
	 */
	if (shared_params->store_derived_key) {
		res = import_derived_key(shared_params, &new_key_object,
					 derived_key, key_len);
		if (res)
			goto exit;
	}

exit:
	TEE_FreeOperation(op_handle);

	TEE_FreeTransientObject(derived_key_obj.handle);

	TEE_FreeTransientObject(new_key_object.handle);

	TEE_FreeTransientObject(ecdh_key_handle);

	if (imported_key_handle.persistent)
		TEE_CloseObject(imported_key_handle.handle);

	if (mem_allocated_to_der_key)
		TEE_Free(derived_key);

	if (private_key)
		TEE_Free(private_key);

	if (public_x)
		TEE_Free(public_x);

	if (public_y)
		TEE_Free(public_y);

	FMSG("%s returned %d\n", __func__, res);

	return res;
}

TEE_Result derive_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG("Executing %s", __func__);

	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct key_derive_shared_params *shared_params = NULL;

	if ((TEE_PARAM_TYPE_GET(param_types, DER_SHARED_PARAM_IDX) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[DER_SHARED_PARAM_IDX].memref.size !=
		    sizeof(*shared_params) ||
	    !params[DER_SHARED_PARAM_IDX].memref.buffer)
		return res;

	shared_params = params[DER_SHARED_PARAM_IDX].memref.buffer;
	if (is_hkdf_algo(shared_params->derive_algo))
		res = hkdf_derive_key(param_types, params);
	else if (shared_params->derive_algo ==
		 TEE_ALG_ECDH_DERIVE_SHARED_SECRET)
		res = ecdh_derive_key(param_types, params);

	FMSG("%s returned %d\n", __func__, res);

	return res;
}
