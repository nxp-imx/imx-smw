// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <psa/protected_storage.h>

#include "compiler.h"
#include "debug.h"

__export psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length,
				 const void *p_data,
				 psa_storage_create_flags_t create_flags)
{
	(void)uid;
	(void)data_length;
	(void)p_data;
	(void)create_flags;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset,
				 size_t data_size, void *p_data,
				 size_t *p_data_length)
{
	(void)uid;
	(void)data_offset;
	(void)data_size;
	(void)p_data;
	(void)p_data_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_ps_get_info(psa_storage_uid_t uid,
				      struct psa_storage_info_t *p_info)
{
	(void)uid;
	(void)p_info;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_ps_remove(psa_storage_uid_t uid)
{
	(void)uid;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_ps_create(psa_storage_uid_t uid, size_t capacity,
				    psa_storage_create_flags_t create_flags)
{
	(void)uid;
	(void)capacity;
	(void)create_flags;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_ps_set_extended(psa_storage_uid_t uid,
					  size_t data_offset,
					  size_t data_length,
					  const void *p_data)
{
	(void)uid;
	(void)data_offset;
	(void)data_length;
	(void)p_data;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export uint32_t psa_ps_get_support(void)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return 0;
}
