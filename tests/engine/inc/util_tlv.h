/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __UTIL_TLV_H__
#define __UTIL_TLV_H__

#include <json_object.h>

#include "types.h"

/**
 * util_tlv_encode_ele_import_tlv() - Create the ELE Key blob to import
 * @subtest: Subtest data
 * @blob: Resulting blob
 * @wrap_key: Key value wrapped
 * @oem_mk_id: OEM Master key identifier
 * @sign_length: Signature length append at the end of the blob
 *
 * This function encodes the blob in a TLV format define by the ELE.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad arguments.
 * -BAD_PARAM_TYPE         - Parameter type is not correct or not supported.
 * -VALUE_NOTFOUND         - Value not found.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_tlv_encode_ele_import_tlv(struct subtest_data *subtest,
				   struct tbuffer *blob,
				   struct tbuffer *wrap_key,
				   unsigned int oem_mk_id, size_t sign_length);

#endif /* __UTIL_TLV_H__ */
