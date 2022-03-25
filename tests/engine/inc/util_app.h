/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */
#ifndef __UTIL_APP_H__
#define __UTIL_APP_H__

#include <pthread.h>
#include <unistd.h>

#define MAX_APP_NAME 20

/**
 * struct app_data - Application data structure
 * @pid:             Application process id
 * @name:            Application name
 * @id:              Application id
 * @test:            Reference on the global test data
 * @key_identifiers: Key identifiers list
 * @op_contexts:     Operation context list
 * @ciphers:         Cipher to verify list
 * @signatures:      Signatures to verify list
 * @threads:         Application threads list
 * @semaphores:      Semaphores list
 * @is_multithread:  Application is multithread
 * @parent_def:      Parent's application object definition
 * @def:             Application test definition
 * @thr_ends:        Thread waiting all test threads
 * @timeout:         Application timeout in seconds
 * @ipc:             Inter-Process object
 */
struct app_data {
	pid_t pid;
	char name[MAX_APP_NAME];
	int id;
	struct test_data *test;
	struct llist *key_identifiers;
	struct llist *op_contexts;
	struct llist *ciphers;
	struct llist *signatures;
	struct llist *threads;
	struct llist *semaphores;
	int is_multithread;
	struct json_object *parent_def;
	struct json_object *def;
	struct thread_ends *thr_ends;
	unsigned int timeout;
	struct ipc_data *ipc;
};

/**
 * util_app_init() - Initialize the application list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_app_init(struct llist **list);

/**
 * util_app_get_active_data() - Get the running application data
 *
 * Return:
 * Pointer to the application data object
 */
struct app_data *util_app_get_active_data(void);

/**
 * util_app_create() - Create a new application in the test list
 * @test: Overall test global data object
 * @app_id: Application identifier
 * @def: Application JSON-C definition
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL               - Fork operation failure
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_app_create(struct test_data *test, unsigned int app_id,
		    struct json_object *def);

/**
 * util_app_fork() - Fork the test to create a new process/application
 * @app: Application object to create
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL               - Fork operation failure
 */
int util_app_fork(struct app_data *app);

/**
 * util_app_wait() - Wait all applications to complete
 * @test: Overall test global data object
 *
 * Return:
 * PASSED  - All applications are passed
 * or any error code (see enum err_num)
 */
int util_app_wait(struct test_data *test);

#endif /* __UTIL_APP_H__ */
