/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __UTIL_DIGEST_H__
#define __UTIL_DIGEST_H__

#include <stdlib.h>
#include <string.h>

#include "util_lib.h"
#include "util_session.h"

#define TV_MSG(_id)	  test_vectors[_id].message
#define TV_MSG_LEN(_id)	  test_vectors[_id].message_length
#define TV_DIGEST(_id)	  test_vectors[_id].digest
#define TV_DIGEST_ND(_id) test_vectors[_id].digest_nd

#define TEST_VECTOR(_mech)                                                     \
	[MECH_ID_##_mech] = { .message = message_##_mech,                      \
			      .message_length = sizeof(message_##_mech),       \
			      .digest = digest_##_mech,                        \
			      .digest_nd = digest_nd_##_mech }

#define DIGEST_MECHANISM(_id) digest_infos[_id].mechanism
#define DIGEST_LENGTH(_id)    digest_infos[_id].length
#define DIGEST_NAME(_id)      digest_infos[_id].name

#define DIGEST_INFO(_mech, _length)                                            \
	[MECH_ID_##_mech] = { .mechanism = CKM_##_mech,                        \
			      .length = _length,                               \
			      .name = #_mech }

enum mechanism_id {
	MECH_ID_SHA_1 = 0,
	MECH_ID_SHA224,
	MECH_ID_SHA256,
	MECH_ID_SHA384,
	MECH_ID_SHA512,
	MECH_ID_SHA3_224,
	MECH_ID_SHA3_256,
	MECH_ID_SHA3_384,
	MECH_ID_SHA3_512,
	MECH_ID_NB
};

struct test_vector {
	const unsigned char *message;
	unsigned long message_length;
	const unsigned char *digest;
	const unsigned char *digest_nd;
};

struct digest_info {
	CK_MECHANISM_TYPE mechanism;
	unsigned long length;
	char *name;
};

extern const unsigned char message_SHA_1[];
extern const unsigned char digest_SHA_1[];
extern const unsigned char digest_nd_SHA_1[];
extern const unsigned char message_SHA224[];
extern const unsigned char digest_SHA224[];
extern const unsigned char digest_nd_SHA_224[];
extern const unsigned char message_SHA_256[];
extern const unsigned char digest_SHA_256[];
extern const unsigned char digest_nd_SHA_256[];
extern const unsigned char message_SHA_384[];
extern const unsigned char digest_SHA_384[];
extern const unsigned char digest_nd_SHA_384[];
extern const unsigned char message_SHA_512[];
extern const unsigned char digest_SHA_512[];
extern const unsigned char digest_nd_SHA_512[];
extern const unsigned char message_SHA3_224[];
extern const unsigned char digest_SHA3_224[];
extern const unsigned char digest_nd_SHA3_224[];
extern const unsigned char message_SHA3_256[];
extern const unsigned char digest_SHA3_256[];
extern const unsigned char digest_nd_SHA3_256[];
extern const unsigned char message_SHA3_384[];
extern const unsigned char digest_SHA3_384[];
extern const unsigned char digest_nd_SHA3_384[];
extern const unsigned char message_SHA3_512[];
extern const unsigned char digest_SHA3_512[];
extern const unsigned char digest_nd_SHA3_512[];
extern struct test_vector test_vectors[];
extern struct digest_info digest_infos[];

bool check_digest_length(unsigned long exp_digest_length,
			 unsigned long digest_length);

bool check_digest(const unsigned char *exp_digest,
		  unsigned long exp_digest_length, const unsigned char *digest,
		  unsigned long digest_length);

#endif /* __UTIL_DIGEST_H__ */
