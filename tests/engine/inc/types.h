/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __TYPES_H__
#define __TYPES_H__

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

extern const struct error list_err[];
extern unsigned int list_err_size;

/**
 * struct common_params - Parameters common to commands.
 * @is_api_test: Define if it's an API test or not
 * @expected_res: Expected result of the command.
 * @subsystem: Subsystem to use for the command.
 * @version: Version of the SMW API.
 */
struct common_parameters {
	int is_api_test;
	int expected_res;
	char *subsystem;
	unsigned int version;
};

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
	t_double
};

#endif /* __TYPES_H__ */
