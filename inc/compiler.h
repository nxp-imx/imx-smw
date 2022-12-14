/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __COMPILER_H__
#define __COMPILER_H__

#define __weak	       __attribute__((weak))
#define __export       __attribute__((visibility("default")))
#define __maybe_unused __attribute__((unused))

#endif /* __COMPILER_H__ */
