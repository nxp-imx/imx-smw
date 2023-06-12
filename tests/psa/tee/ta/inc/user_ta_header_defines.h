/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#define TA_UUID                                                                \
	{                                                                      \
		0x1682dada, 0x20de, 0x4b02,                                    \
		{                                                              \
			0x9e, 0xaa, 0x28, 0x47, 0x76, 0x93, 0x12, 0x33         \
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
#define TA_DESCRIPTION "SMW PSA TEST TA"

#endif /* USER_TA_HEADER_DEFINES_H */
