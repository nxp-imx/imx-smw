/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __LIFECYCLE_H__
#define __LIFECYCLE_H__

/**
 * smw_lifecycle_set_tlv() - Build the lifecycle TLV variable list
 * @attrs: [in/out] TLV variable-length list
 * @attrs_len: [in/out] Size in bytes of @attrs
 * @lc_flags: [in] SMW's lifecycle flags
 *
 * Builds the TLV variable length list of the object's lifecycle.
 * The @attrs buffer is allocated/reallocated on the need.
 * The @attrs_length returns the @attrs total length.
 *
 * Return:
 * SMW_STATUS_OK                - Success.
 * SMW_STATUS_INVALID_PARAM     - One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE     - Memory allocation failure.
 * SMW_STATUS_OPERATION_FAILURE - Any other failure.
 */
int smw_lifecycle_set_tlv(unsigned char **attrs, unsigned int *attrs_len,
			  unsigned long lc_flags);

/**
 * smw_lifecycle_get_tlv() - Get the lifecycle flags from TLV variable list
 * @lc_flags: [out] SMW's lifecycle flags
 * @attrs: [in] TLV variable-length list
 * @attrs_len: [in] Size in bytes of @attrs
 *
 * Parses the lifecycle TLV variable length list and returns SMW's lifecycle
 * flags.
 *
 * Return:
 * SMW_STATUS_OK                - Success.
 * SMW_STATUS_INVALID_PARAM     - One of the parameter is invalid.
 * SMW_STATUS_INVALID_LIFECYCLE - Invalid TLV
 */
int smw_lifecycle_get_tlv(unsigned long *lc_flags, unsigned char *attrs,
			  unsigned int attrs_len);

#endif /* __LIFECYCLE_H__ */
