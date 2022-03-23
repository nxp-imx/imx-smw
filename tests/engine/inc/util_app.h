/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */
#ifndef __UTIL_APP_H__
#define __UTIL_APP_H__

#include <unistd.h>

#define MAX_APP_NAME 20

/**
 * struct app_data - Application data structure
 * @pid:             Application process id
 * @name:            Application name
 * @test:            Reference on the global test data
 * @key_identifiers: Key identifiers list
 * @op_contexts:     Operation context list
 * @ciphers:         Cipher to verify list
 * @signatures:      Signatures to verify list
 * @threads:         Application threads list
 * @semaphores:      Semaphores list
 * @is_multithread:  Application is multithread
 * @definition:      Application test definition
 * @thr_ends:        Thread waiting all test threads
 * @timeout:         Application timeout in seconds
 */
struct app_data {
	pid_t pid;
	char name[MAX_APP_NAME];
	struct test_data *test;
	struct llist *key_identifiers;
	struct llist *op_contexts;
	struct llist *ciphers;
	struct llist *signatures;
	struct llist *threads;
	struct llist *semaphores;
	int is_multithread;
	struct json_object *definition;
	struct thread_ends *thr_ends;
	unsigned int timeout;
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
 * util_register_app() - Register an application
 * @test: Overall test global data object
 * @id: Application identifier
 * @data: Application data object allocated
 *
 * Allocate and initialize the application data.
 * Register the application in the test @apps list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_app_register(struct test_data *test, unsigned int id,
		      struct app_data **data);

/**
 * util_app_get_active_data() - Get the running application data
 *
 * Return:
 * Pointer to the application data object
 */
struct app_data *util_app_get_active_data(void);

#endif /* __UTIL_APP_H__ */
