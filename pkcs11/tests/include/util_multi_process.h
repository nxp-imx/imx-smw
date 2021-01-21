/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __UTIL_MULTI_PROCESS_H__
#define __UTIL_MULTI_PROCESS_H__

#include <semaphore.h>

#include <pkcs11smw.h>

#define SHM_NAME_MAX 50

struct mp_shm {
	int fd;
	char name[SHM_NAME_MAX];
	void *data;
	size_t size;
	sem_t semread;
	sem_t semwrite;
};

struct mp_args {
	struct mp_shm shm;
	int child;
	pid_t pid;
	void *lib_hdl;
	CK_FUNCTION_LIST_PTR pfunc;
	char *testname;
	int (*test_func)(struct mp_args *args);
};

int run_multi_process(struct mp_args *args);
int util_create_open_shm(struct mp_args *args);
int util_close_shm(struct mp_args *args);

#endif /* __UTIL_MULTI_PROCESS_H__ */
