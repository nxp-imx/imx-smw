/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2024, 2026 NXP
 */

#ifndef __COMPILER_H__
#define __COMPILER_H__

#define __weak	       __attribute__((weak))
#define __export       __attribute__((visibility("default")))
#define __maybe_unused __attribute__((unused))
#define __packed       __attribute__((packed))
#define __fallthrough  __attribute__((fallthrough))
#define __format_printf(_m, _n) __attribute__((__format__(__printf__, _m, _n)));

#endif /* __COMPILER_H__ */
