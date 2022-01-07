/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __RUN_THREAD_H__
#define __RUN_THREAD_H__

/**
 * process_thread() - Thread execution routine
 * @arg: Thread process argument
 *
 * Parses the thread test definition and foreach "subtest" tag
 * executes the subtest operation.
 *
 * Return:
 * Pointer to the subtest status
 */
void *process_thread(void *arg);

#endif /* __RUN_THREAD_H__ */
