/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __TYPES_H__
#define __TYPES_H__

#include <assert.h>
#include <stdio.h>

/* List of key type */
#define BR1_KEY	       "BRAINPOOL_R1"
#define BT1_KEY	       "BRAINPOOL_T1"
#define NIST_KEY       "NIST"
#define RSA_KEY	       "RSA"
#define TLS_MASTER_KEY "TLS_MASTER_KEY"

/* Type of errors */
enum err_num {
	PASSED = 0,
	FAILED,
	INTERNAL,
	INTERNAL_OUT_OF_MEMORY,
	UNDEFINED_CMD,
	MISSING_PARAMS, /* 5 */
	UNKNOWN_RESULT,
	BAD_RESULT, /* Result differs from expected */
	BAD_ARGS,
	SUBSYSTEM,
	NOT_RUN, /* 10 */
	BAD_PARAM_TYPE,
	VALUE_NOTFOUND,
	KEY_NOTFOUND,
	ERROR_NOT_DEFINED,
	ERROR_SMWLIB_INIT, /* 15 */
	MUTEX_DESTROY,
	COND_DESTROY,
	TIMEOUT,
	THREAD_CANCELED,
	MAX_TEST_ERROR, /* Maximum test error constant - keep last item */
};

/**
 * struct error
 * @code: Error code.
 * @status: Error status.
 */
struct error {
	int code;
	const char *status;
};

extern const struct error list_err[MAX_TEST_ERROR];

/*
 * Opaque type of thread waiting all test thread
 */
struct thread_ends;

/**
 * struct app_data - Application data structure
 * @dir_def_file:    Folder of the test definition file
 * @key_identifiers: Key identifiers list
 * @op_contexts:     Operation context list
 * @ciphers:         Cipher to verify list
 * @signatures:      Signatures to verify list
 * @threads:         Application threads list
 * @semaphores:      Semaphores list
 * @log:             Application log file
 * @is_multithread:  Application is multithread
 * @is_api_test:     Flag if test only SMW's API
 * @definition:      Application test definition
 * @lock_dbg:        Debug Printf protector
 * @lock_log:        Log into file protector
 * @thr_ends:        Thread waiting all test threads
 * @timeout:         Application timeout in seconds
 */
struct app_data {
	char *dir_def_file;
	struct llist *key_identifiers;
	struct llist *op_contexts;
	struct llist *ciphers;
	struct llist *signatures;
	struct llist *threads;
	struct llist *semaphores;
	FILE *log;
	int is_multithread;
	int is_api_test;
	struct json_object *definition;
	void *lock_dbg;
	void *lock_log;
	struct thread_ends *thr_ends;
	unsigned int timeout;
};

/**
 * struct cmn_params - Parameters common to commands.
 * @app: Application data.
 * @expected_res: Expected result of the command.
 * @subsystem: Subsystem to use for the command.
 * @version: Version of the SMW API.
 */
struct cmn_params {
	struct app_data *app;
	int expected_res;
	char *subsystem;
	unsigned int version;
};

#define is_api_test(this)                                                      \
	({                                                                     \
		struct cmn_params *_this = (this);                             \
		assert(_this->app);                                            \
		_this->app->is_api_test;                                       \
	})

#define list_keys(this)                                                        \
	({                                                                     \
		struct cmn_params *_this = (this);                             \
		assert(_this->app);                                            \
		_this->app->key_identifiers;                                   \
	})

#define list_op_ctxs(this)                                                     \
	({                                                                     \
		struct cmn_params *_this = (this);                             \
		assert(_this->app);                                            \
		_this->app->op_contexts;                                       \
	})

#define list_ciphers(this)                                                     \
	({                                                                     \
		struct cmn_params *_this = (this);                             \
		assert(_this->app);                                            \
		_this->app->ciphers;                                           \
	})

#define list_signatures(this)                                                  \
	({                                                                     \
		struct cmn_params *_this = (this);                             \
		assert(_this->app);                                            \
		_this->app->signatures;                                        \
	})

/**
 * struct tbuffer - Data of type buffer
 * @data: Data buffer
 * @length: Length of the data buffer
 */
struct tbuffer {
	unsigned char *data;
	unsigned int length;
};

enum t_data_type {
	t_boolean = 0,
	t_int,
	t_string,
	t_object,
	t_buffer,
	t_buffer_hex,
	t_int64,
	t_double,
	t_sem
};

#endif /* __TYPES_H__ */
