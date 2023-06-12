/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#define TA_UUID                                                                \
	{                                                                      \
		0x11b5c4aa, 0x6d20, 0x11ea,                                    \
		{                                                              \
			0xbc, 0x55, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03         \
		}                                                              \
	}

/* TA FLAGS */
#define TA_FLAGS (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)

/* TA Stack size */
#define TA_STACK_SIZE (2 * 1024)

/* TA Data size */
#define TA_DATA_SIZE (32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION "1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION "SMW TEST TA"

#endif /* USER_TA_HEADER_DEFINES_H */
