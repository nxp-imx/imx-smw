/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2024 NXP
 */

#ifndef __LIB_DIGEST_H__
#define __LIB_DIGEST_H__

struct libdig_params {
	CK_BYTE_PTR pData;
	CK_ULONG ulDataLen;
	CK_BYTE_PTR pDigest;
	CK_ULONG_PTR pulDigestLen;
};

/**
 * lib_digest_copy_operation() - Create a copy of the multi-part digest
 * operation, if active
 * @src: The source context
 * @dst: The destination context
 *
 * Check if any multi-part digest operation is active.
 * If a multi-part operation is active, copy the operation
 * context into @dst.
 *
 * Return:
 * CKR_STATE_UNSAVEABLE               - State cannot be saved
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_FUNCTION_FAILED                - Operation failed
 * CKR_OBJECT_HANDLE_INVALID          - Object not found
 * CKR_DEVICE_ERROR                   - Device failure
 * CKR_OK                             - Success
 */
CK_RV lib_digest_copy_operation(void *src, void **dst);

#endif /* __LIB_DIGEST_H__ */
