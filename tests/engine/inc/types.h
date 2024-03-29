/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef __TYPES_H__
#define __TYPES_H__

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

#include "util_app.h"

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
	API_STATUS_NOK, /* SMW Call return a status not ok */
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
	BAD_SUBSYSTEM, /* 20 */
	UNDEFINED_API,
	DATA_NOTFOUND,
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
 * struct test_data - Overall test data
 * @name:            Test name
 * @dir_def_file:    Folder of the test definition file
 * @log:             Application log file
 * @lock_log:        Log into file protector
 * @lock_dbg:        Debug printf protector
 * @is_api_test:     Flag if test only SMW's API
 * @is_multi_app:    Flag if test is multiple applications
 * @definition:      Test definition
 * @nb_apps:         Number of applications
 * @apps:            Application list object
 */
struct test_data {
	char *name;
	char *dir_def_file;
	FILE *log;
	void *lock_log;
	void *lock_dbg;
	int is_api_test;
	int is_multi_apps;
	struct json_object *definition;
	size_t nb_apps;
	struct llist *apps;
};

/**
 * struct subtest_data - Subtest data object
 * @params: JSON-C Subtest parameters object
 * @app: Application data.
 * @name: Name of the subtest running
 * @status: Subtest status (reference to subtests_stat.status_array entry)
 * @api_status: API call status
 * @smw_status: SMW API call status
 * @psa_status: PSA API call status
 * @subsystem: Subsystem to use for the command
 * @api: API to use for the command
 * @version: Version of the SMW API
 */
struct subtest_data {
	struct json_object *params;
	struct app_data *app;
	char *name;
	int *status;
	union {
		int api_status;
		int smw_status;
		int psa_status;
	};
	char *subsystem;
	char *api;
	unsigned char version;
};

#define is_api_test(this)                                                      \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		assert(_this->app->test);                                      \
		_this->app->test->is_api_test;                                 \
	})

#define list_keys(this)                                                        \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->keys;                                              \
	})

#define list_data(this)                                                        \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->data;                                              \
	})

#define list_op_ctxs(this)                                                     \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->op_contexts;                                       \
	})

#define list_ciphers(this)                                                     \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->ciphers;                                           \
	})

#define list_signatures(this)                                                  \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->signatures;                                        \
	})

#define list_macs(this)                                                        \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->macs;                                              \
	})

#define list_certificates(this)                                                \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->certificates;                                      \
	})

#define list_aeads(this)                                                       \
	({                                                                     \
		struct subtest_data *_this = (this);                           \
		assert(_this->app);                                            \
		_this->app->aeads;                                             \
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
	t_int8,
	t_int,
	t_string,
	t_object,
	t_buffer,
	t_buffer_hex,
	t_int64,
	t_double,
	t_sem,
	t_ints,
	t_array
};

#endif /* __TYPES_H__ */
