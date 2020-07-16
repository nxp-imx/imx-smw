/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <tee_subsystem.h>

#define TA_UUID SMW_TA_UUID

/* TA FLAGS */
#define TA_FLAGS TA_FLAG_EXEC_DDR

/* TA Stack size */
#define TA_STACK_SIZE (2 * 1024)

/* TA Data size */
#define TA_DATA_SIZE (32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION "1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION "SMW OPTEE SIDE"

#endif /* USER_TA_HEADER_DEFINES_H */
