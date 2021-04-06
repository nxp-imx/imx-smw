/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __LIB_DIGEST_H__
#define __LIB_DIGEST_H__

struct libdig_params {
	CK_BYTE_PTR pData;
	CK_ULONG ulDataLen;
	CK_BYTE_PTR pDigest;
	CK_ULONG_PTR pulDigestLen;
};

#endif /* __LIB_DIGEST_H__ */
