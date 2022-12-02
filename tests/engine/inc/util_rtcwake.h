/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_RTCWAKE_H__
#define __UTIL_RTCWAKE_H__

/**
 * util_rtcwake_suspend_to_mem() - Suspend device mem mode
 * @sec: Number of seconds to suspend
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the argument is bad.
 * -INTERNAL                - Internal function failed.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 */
int util_rtcwake_suspend_to_mem(int sec);

#endif /* __UTIL_RTCWAKE_H__ */
