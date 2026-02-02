// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <zephyr/kernel.h>
#include <stdlib.h>

#include "internal.h"

#define THREAD_PRIORITY 5

struct thread_wrapper {
	struct k_thread thread;
	k_thread_stack_t *stack;
	void *(*start_routine)(void *arg);
	void *arg;
};

struct thread_handle {
	k_tid_t tid;
	struct thread_wrapper *wrapper;
};

static void thread_wrapper(void *p1, void *p2, void *p3)
{
	struct thread_wrapper *wrapper = (struct thread_wrapper *)p1;

	(void)p2;
	(void)p3;

	if (wrapper && wrapper->start_routine)
		wrapper->start_routine(wrapper->arg);

	if (wrapper) {
		if (wrapper->stack)
			k_thread_stack_free(wrapper->stack);

		k_free(wrapper);
	}
}

static void free_handle(struct thread_handle *handle)
{
	if (!handle)
		return;

	if (handle->wrapper) {
		if (handle->wrapper->stack)
			k_thread_stack_free(handle->wrapper->stack);

		k_free(handle->wrapper);
	}

	k_free(handle);
}

int osal_zephyr_thread_create(unsigned long *thread,
			      void *(*start_routine)(void *), void *arg)
{
	struct thread_handle *handle = NULL;
	struct thread_wrapper *wrapper = NULL;

	if (!thread || !start_routine)
		goto error;

	handle = k_malloc(sizeof(struct thread_handle));
	if (!handle)
		goto error;

	wrapper = k_malloc(sizeof(struct thread_wrapper));
	if (!wrapper)
		goto error;

	handle->wrapper = wrapper;

	wrapper->start_routine = start_routine;
	wrapper->arg = arg;
	wrapper->stack = k_thread_stack_alloc(CONFIG_SMW_THREAD_STACK_SIZE, 0);
	if (!wrapper->stack)
		goto error;

	handle->tid = k_thread_create(&wrapper->thread, wrapper->stack,
				      CONFIG_SMW_THREAD_STACK_SIZE,
				      thread_wrapper, wrapper, NULL, NULL,
				      THREAD_PRIORITY, 0, K_NO_WAIT);

	if (!handle->tid)
		goto error;

	*thread = (uintptr_t)handle;

	return 0;

error:
	free_handle(handle);

	return -1;
}

int osal_zephyr_thread_cancel(unsigned long thread)
{
	struct thread_handle *handle = (struct thread_handle *)thread;

	if (!handle)
		return -1;

	k_thread_abort(handle->tid);
	k_thread_join(handle->tid, K_FOREVER);
	free_handle(handle);

	return 0;
}
