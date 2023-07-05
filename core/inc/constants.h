/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#define SMW_STORAGE_READ_ONLY  1UL
#define SMW_STORAGE_READ_ONCE  2UL
#define SMW_STORAGE_WRITE_ONLY 4UL

#define SMW_LIFECYCLE_CURRENT	    0UL
#define SMW_LIFECYCLE_OPEN	    1UL
#define SMW_LIFECYCLE_CLOSED	    2UL
#define SMW_LIFECYCLE_CLOSED_LOCKED 4UL

#endif /* __CONSTANTS_H__ */
