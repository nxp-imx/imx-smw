/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef TEE_SUBSYSTEM_H
#define TEE_SUBSYSTEM_H

#define SMW_TA_UUID                                                            \
	{                                                                      \
		0x11b5c4aa, 0x6d20, 0x11ea,                                    \
		{                                                              \
			0xbc, 0x55, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03         \
		}                                                              \
	}

/* TEE key type */
enum tee_key_type {
	TEE_KEY_TYPE_ID_ECDSA,
	TEE_KEY_TYPE_ID_AES,
	TEE_KEY_TYPE_ID_DES,
	TEE_KEY_TYPE_ID_DES3,
	TEE_KEY_TYPE_ID_HMAC_MD5,
	TEE_KEY_TYPE_ID_HMAC_SHA1,
	TEE_KEY_TYPE_ID_HMAC_SHA224,
	TEE_KEY_TYPE_ID_HMAC_SHA256,
	TEE_KEY_TYPE_ID_HMAC_SHA384,
	TEE_KEY_TYPE_ID_HMAC_SHA512,
	TEE_KEY_TYPE_ID_HMAC_SM3,
	TEE_KEY_TYPE_ID_NB,
	TEE_KEY_TYPE_ID_INVALID
};

/* TEE algorithm ID */
enum tee_algorithm_id {
	TEE_ALGORITHM_ID_MD5,
	TEE_ALGORITHM_ID_SHA1,
	TEE_ALGORITHM_ID_SHA224,
	TEE_ALGORITHM_ID_SHA256,
	TEE_ALGORITHM_ID_SHA384,
	TEE_ALGORITHM_ID_SHA512,
	TEE_ALGORITHM_ID_SM3,
	TEE_ALGORITHM_ID_INVALID
};

/* Key manager commands */
#define CMD_GENERATE_KEY 0
#define CMD_DELETE_KEY	 1
#define CMD_IMPORT_KEY	 2
#define CMD_EXPORT_KEY	 3
#define CMD_HASH	 4
#define CMD_SIGN	 5
#define CMD_VERIFY	 6
#define CMD_HMAC	 7

struct hmac_shared_params {
	enum tee_key_type tee_key_type;
	enum tee_algorithm_id tee_algorithm_id;
	unsigned int security_size;
};

#endif /* TEE_SUBSYSTEM_H */
