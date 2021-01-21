/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __COMPILER_H__
#define __COMPILER_H__

#define __printf(st, ft) __attribute__((__format__(__printf__, st, ft)));

#endif /* __COMPILER_H__ */
