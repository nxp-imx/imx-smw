/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#include "builtin_macros.h"

#define SMW_STORAGE_READ_ONLY  BIT(0)
#define SMW_STORAGE_READ_ONCE  BIT(1)
#define SMW_STORAGE_WRITE_ONLY BIT(2)

#define SMW_LIFECYCLE_CURRENT	    BIT(0)
#define SMW_LIFECYCLE_OPEN	    BIT(1)
#define SMW_LIFECYCLE_CLOSED	    BIT(2)
#define SMW_LIFECYCLE_CLOSED_LOCKED BIT(3)
#define SMW_LIFECYCLE_OEM_RETURN    BIT(4)
#define SMW_LIFECYCLE_NXP_RETURN    BIT(5)

#endif /* __CONSTANTS_H__ */
