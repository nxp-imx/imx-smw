/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
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
	TEE_KEY_TYPE_ID_NB,
	TEE_KEY_TYPE_ID_INVALID
};

/* Key manager commands */
#define CMD_GENERATE_KEY 0
#define CMD_DELETE_KEY	 1

#endif /* TEE_SUBSYSTEM_H */
