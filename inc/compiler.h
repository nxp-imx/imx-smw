/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2024, 2026 NXP
 */

#ifndef __COMPILER_H__
#define __COMPILER_H__

#ifndef __weak
#define __weak	       __attribute__((weak))
#endif
#define __export       __attribute__((visibility("default")))
#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif
#ifndef __packed
#define __packed       __attribute__((packed))
#endif
#ifndef __fallthrough
#define __fallthrough  __attribute__((fallthrough))
#endif
#define __format_printf(_m, _n) __attribute__((__format__(__printf__, _m, _n)));

#define __no_optimization __attribute__((optimize("O0")))

#endif /* __COMPILER_H__ */
