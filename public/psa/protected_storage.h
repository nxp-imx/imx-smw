/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_PROTECTED_STORAGE_H__
#define __PSA_PROTECTED_STORAGE_H__

#include <psa/storage_common.h>

/**
 * DOC: Reference
 * Documentation:
 *	PSA Storage API v1.0.0 section 5.3 Protected Storage API
 * Link:
 *	https://armkeil.blob.core.windows.net/developer/Files/pdf/PlatformSecurityArchitecture/Implement/IHI0087-PSA_Storage_API-1.0.0.pdf
 */

/**
 * DOC: PSA_PS_API_VERSION_MAJOR
 * The major version number of the PSA PS API.
 *
 * It will be incremented on significant updates that may include breaking changes.
 */
#define PSA_PS_API_VERSION_MAJOR 1

/**
 * DOC: PSA_PS_API_VERSION_MINOR
 * The minor version number of the PSA PS API.
 *
 * It will be incremented in small updates that are unlikely to include breaking changes.
 */
#define PSA_PS_API_VERSION_MINOR 0

/**
 * psa_ps_set() - Create a new or modify an existing key/value pair.
 * @uid: The identifier for the data.
 * @data_length: The size in bytes of the data in @p_data.
 * @p_data: A buffer containing the data.
 * @create_flags: The flags indicating the properties of the data.
 *
 * **Warning: Not supported**
 *
 * The newly created asset has a capacity and size that are equal to @data_length.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The operation completed successfully.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The operation failed because the provided @uid value was already created with
 *	PSA_STORAGE_FLAG_WRITE_ONCE.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one or more of the given arguments were invalid.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The operation failed because one or more of the flags provided in @create_flags is not
 *	supported or is not valid.
 * * PSA_ERROR_INSUFFICIENT_STORAGE:
 *	The operation failed because there was insufficient space on the storage medium.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_GENERIC_ERROR:
 *	The operation failed because of an unspecified internal failure.
 */
psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length,
			const void *p_data,
			psa_storage_create_flags_t create_flags);

/**
 * psa_ps_get() - Retrieve data associated with a provided uid.
 * @uid: The uid value.
 * @data_offset: The starting offset of the data requested.
 * @data_size: The amount of data requested.
 * @p_data: On success, the buffer where the data will be placed.
 * @p_data_length: On success, will contain size of the data placed in @p_data.
 *
 * **Warning: Not supported**
 *
 * Retrieves up to @data_size bytes of the data associated with @uid, starting at @data_offset
 * bytes from the beginning of the data. Upon successful completion, the data will be placed in the
 * @p_data buffer, which must be at least @data_size bytes in size. The length of the data returned
 * will be in @p_data_length. If @data_size is 0, the contents of @p_data_length will be set to
 * zero.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The operation completed successfully.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one of the provided arguments (e.g. @p_data, @p_data_length) is
 *	invalid, for example is NULL or references memory the caller cannot access. In addition,
 *	this can also happen if @data_offset is larger than the size of the data associated with
 *	@uid.
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	The operation failed because the provided @uid value was not found in the storage.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_GENERIC_ERROR:
 *	The operation failed because of an unspecified internal failure.
 * * PSA_ERROR_DATA_CORRUPT:
 *	The operation failed because of an authentication failure when attempting to get the key.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The operation failed because the data associated with the @uid failed authentication.
 */
psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset,
			size_t data_size, void *p_data, size_t *p_data_length);

/**
 * psa_ps_get_info() - Retrieve the metadata about the provided uid.
 * @uid: The identifier for the data.
 * @p_info: A pointer to the psa_storage_info_t struct that will be populated with the metadata.
 *
 * **Warning: Not supported**
 *
 * Retrieves the metadata stored for a given @uid as a &struct psa_storage_info_t.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The operation completed successfully.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one or more of the given arguments were invalid (null pointer,
 *	wrong flags and so on).
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	The operation failed because the provided @uid value was not found in the storage.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_GENERIC_ERROR:
 *	The operation failed because of an unspecified internal failure.
 * * PSA_ERROR_DATA_CORRUPT:
 *	The operation failed because of an authentication failure when attempting to get the key.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The operation failed because the data associated with the @uid failed authentication.
 */
psa_status_t psa_ps_get_info(psa_storage_uid_t uid,
			     struct psa_storage_info_t *p_info);

/**
 * psa_ps_remove() - Remove the provided uid and its associated data from the storage.
 * @uid: The identifier for the data to be removed.
 *
 * **Warning: Not supported**
 *
 * Removes previously stored data and any associated metadata, including rollback protection data.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The operation completed successfully.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one or more of the given arguments were invalid (null pointer,
 *	wrong flags and so on).
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	The operation failed because the provided @uid value was not found in the storage.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The operation failed because the provided @uid value was created with
 *	PSA_STORAGE_FLAG_WRITE_ONCE.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_GENERIC_ERROR:
 *	The operation failed because of an unspecified internal failure.
 */
psa_status_t psa_ps_remove(psa_storage_uid_t uid);

/**
 * psa_ps_create()
 * @uid: A unique identifier for the asset.
 * @capacity: The allocated capacity, in bytes, of the @uid.
 * @create_flags: Flags indicating properties of the storage.
 *
 * **Warning: Not supported**
 *
 * Reserves storage for the specified @uid. Upon success, the capacity of the storage is @capacity,
 * and the size is 0. It is only necessary to call this function for assets that will be written
 * with the psa_ps_set_extended() function. If only psa_ps_set() is needed, calls to this function
 * are redundant.
 *
 * This function cannot be used to replace an existing asset, and attempting to do so will return
 * PSA_ERROR_ALREADY_EXISTS.
 *
 * If the PSA_STORAGE_FLAG_WRITE_ONCE flag is passed, psa_ps_create() will return
 * PSA_ERROR_NOT_SUPPORTED.
 *
 * This function is supported only if the psa_ps_get_support() returns
 * PSA_STORAGE_SUPPORT_SET_EXTENDED.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The storage was successfully reserved.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_INSUFFICIENT_STORAGE:
 *	@capacity is bigger than the current available space.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The function is not implemented or one or more @create_flags are not supported.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@uid was 0 or @create_flags specified flags that are not defined in the API.
 * * PSA_ERROR_GENERIC_ERROR:
 *	The operation has failed due to an unspecified error.
 * * PSA_ERROR_ALREADY_EXISTS:
 *	Storage for the specified @uid already exists.
 */
psa_status_t psa_ps_create(psa_storage_uid_t uid, size_t capacity,
			   psa_storage_create_flags_t create_flags);

/**
 * psa_ps_set_extended()
 * @uid: The unique identifier for the asset.
 * @data_offset: Offset within the asset to start the write.
 * @data_length: The size in bytes of the data in @p_data to write.
 * @p_data: Pointer to a buffer which contains the data to write.
 *
 * **Warning: Not supported**
 *
 * Sets partial data into an asset based on the given @uid, @data_offset, @data_length and
 * @p_data.
 *
 * Before calling this function, the storage must have been reserved with a call to
 * psa_ps_create(). It can also be used to overwrite data in an asset that was created with a call
 * to psa_ps_set().
 *
 * Calling this function with @data_length = 0 is permitted. This makes no change to the stored
 * data.
 *
 * This function can overwrite existing data and/or extend it up to the
 * capacity for the @uid specified in psa_ps_create, but cannot create gaps. That is, it has
 * preconditions\:
 *
 * - data_offset <= size
 * - data_offset + data_length <= capacity
 *
 * and postconditions\:
 *
 * - size = max(size, data_offset + data_length)
 * - capacity unchanged.
 *
 * This function is supported only if the psa_ps_get_support() returns
 * PSA_STORAGE_SUPPORT_SET_EXTENDED.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The asset exists, the input parameters are correct and the data is correctly written in the
 *	physical storage.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The data was not written correctly in the physical storage.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one or more of the preconditions listed above regarding
 *	@data_offset, size, or @data_length was violated.
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	The specified @uid was not found.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The implementation of the API does not support this function.
 * * PSA_ERROR_GENERIC_ERROR:
 *	The operation failed due to an unspecified error.
 * * PSA_ERROR_DATA_CORRUPT:
 *	The operation failed because the existing data has been corrupted.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The operation failed because the existing data failed authentication (MAC check failed).
 * * PSA_ERROR_NOT_PERMITTED:
 *	The operation failed because it was attempted on an asset which was written with the flag
 *	PSA_STORAGE_FLAG_WRITE_ONCE.
 */
psa_status_t psa_ps_set_extended(psa_storage_uid_t uid, size_t data_offset,
				 size_t data_length, const void *p_data);

/**
 * psa_ps_get_support()
 *
 * **Warning: Not supported**
 *
 * Returns a bitmask with flags set for all of the optional features supported by the
 * implementation.
 *
 * Currently defined flags are limited to\:
 *
 * - PSA_STORAGE_SUPPORT_SET_EXTENDED
 *
 * Return:
 * uint32_t
 */
uint32_t psa_ps_get_support(void);

#endif /* __PSA_PROTECTED_STORAGE_H__ */
