// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "psa/error.h"

#include "smw_status.h"

psa_status_t util_smw_to_psa_status(enum smw_status_code status)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;

	switch (status) {
	case SMW_STATUS_OK:
	case SMW_STATUS_KEY_POLICY_WARNING_IGNORED:
		psa_status = PSA_SUCCESS;
		break;

	case SMW_STATUS_UNKNOWN_ID:
		psa_status = PSA_ERROR_INVALID_HANDLE;
		break;

	case SMW_STATUS_ALLOC_FAILURE:
	case SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY:
		psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
		break;

	case SMW_STATUS_INVALID_PARAM:
	case SMW_STATUS_KEY_INVALID:
		psa_status = PSA_ERROR_INVALID_ARGUMENT;
		break;

	case SMW_STATUS_OPERATION_NOT_SUPPORTED:
		psa_status = PSA_ERROR_NOT_SUPPORTED;
		break;

	case SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED:
	case SMW_STATUS_OPERATION_NOT_CONFIGURED:
	case SMW_STATUS_DATA_ALREADY_RETRIEVED:
		psa_status = PSA_ERROR_NOT_PERMITTED;
		break;

	case SMW_STATUS_SIGNATURE_INVALID:
	case SMW_STATUS_SIGNATURE_LEN_INVALID:
		psa_status = PSA_ERROR_INVALID_SIGNATURE;
		break;

	case SMW_STATUS_OUTPUT_TOO_SHORT:
		psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
		break;

	case SMW_STATUS_SUBSYSTEM_STORAGE_NO_SPACE:
	case SMW_STATUS_SUBSYSTEM_STORAGE_ERROR:
		psa_status = PSA_ERROR_STORAGE_FAILURE;
		break;

	case SMW_STATUS_SUBSYSTEM_CORRUPT_OBJECT:
		psa_status = PSA_ERROR_DATA_CORRUPT;
		break;

	case SMW_STATUS_OBJ_DB_GET_INFO:
		psa_status = PSA_ERROR_INVALID_HANDLE;
		break;

	default:
		break;
	}

	return psa_status;
}
