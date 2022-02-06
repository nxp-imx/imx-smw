/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_INTERNAL_TRUSTED_STORAGE_H__
#define __PSA_INTERNAL_TRUSTED_STORAGE_H__

#include "psa/storage_common.h"

/**
 * DOC: Reference
 * Documentation:
 *	PSA Storage API v1.0.0 section 5.2 Internal Trusted Storage API
 * Link:
 *	https://armkeil.blob.core.windows.net/developer/Files/pdf/PlatformSecurityArchitecture/Implement/IHI0087-PSA_Storage_API-1.0.0.pdf
 */

/**
 * DOC: PSA_ITS_API_VERSION_MAJOR
 * The major version number of the PSA ITS API.
 *
 * It will be incremented on significant updates that may include breaking changes.
 */
#define PSA_ITS_API_VERSION_MAJOR 1

/**
 * DOC: PSA_ITS_API_VERSION_MINOR
 * The minor version number of the PSA ITS API.
 *
 * It will be incremented in small updates that are unlikely to include breaking changes.
 */
#define PSA_ITS_API_VERSION_MINOR 0

/**
 * psa_its_set() - Create a new, or modify an existing, uid/value pair.
 * @uid: The identifier for the data.
 * @data_length: The size in bytes of the data in @p_data.
 * @p_data: A buffer containing the data.
 * @create_flags: The flags that the data will be stored with.
 *
 * **Warning: Not supported**
 *
 * Stores data in the internal storage.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The operation completed successfully.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The operation failed because the provided @uid value was already created with
 *	PSA_STORAGE_FLAG_WRITE_ONCE.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The operation failed because one or more of the flags provided in @create_flags is not
 *	supported or is not valid.
 * * PSA_ERROR_INSUFFICIENT_STORAGE:
 *	The operation failed because there was insufficient space on the storage medium.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one of the provided pointers (e.g. @p_data) is invalid, for
 *  example is NULL or references memory the caller cannot access.
 */
psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length,
			 const void *p_data,
			 psa_storage_create_flags_t create_flags);

/**
 * psa_its_get() - Retrieve data associated with a provided UID.
 * @uid: The uid value.
 * @data_offset: The starting offset of the data requested.
 * @data_size: The amount of data requested.
 * @p_data: On success, the buffer where the data will be placed.
 * @p_data_length: On success, this will contain size of the data placed in @p_data.
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
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	The operation failed because the provided @uid value was not found in the storage.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one of the provided arguments (e.g. @p_data, @p_data_length) is
 *	invalid, for example is NULL or references memory the caller cannot access. In addition,
 *	this can also happen if @data_offset is larger than the size of the data associated with
 *	@uid.
 */
psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset,
			 size_t data_size, void *p_data, size_t *p_data_length);

/**
 * psa_its_get_info() - Retrieve the metadata about the provided @uid.
 * @uid: The uid value.
 * @p_info: A pointer to the &struct psa_storage_info_t that will be populated with the metadata.
 *
 * **Warning: Not supported**
 *
 * Retrieves the metadata stored for a given @uid as a &struct psa_storage_info_t.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The operation completed successfully.
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	The operation failed because the provided @uid value was not found in the storage.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one of the provided pointers (e.g. @p_info) is invalid, for
 *  example is NULL or references memory the caller cannot access.
 */
psa_status_t psa_its_get_info(psa_storage_uid_t uid,
			      struct psa_storage_info_t *p_info);

/**
 * psa_its_remove() - Remove the provided key and its associated data from the storage.
 * @uid: The uid value.
 *
 * **Warning: Not supported**
 *
 * Deletes the data from internal storage.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The operation completed successfully.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The operation failed because one or more of the given arguments were invalid (null pointer,
 *	wrong flags and so on).
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	The operation failed because the provided key value was not found in the storage.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The operation failed because the provided key value was created with
 *	PSA_STORAGE_FLAG_WRITE_ONCE.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The operation failed because the physical storage has failed (Fatal error).
 */
psa_status_t psa_its_remove(psa_storage_uid_t uid);

#endif /* __PSA_INTERNAL_TRUSTED_STORAGE_H__ */
