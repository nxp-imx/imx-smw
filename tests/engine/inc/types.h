/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __TYPES_H__
#define __TYPES_H__

/* List of key type */
#define AES_KEY	      "AES"
#define BR1_KEY	      "BRAINPOOL_R1"
#define BT1_KEY	      "BRAINPOOL_T1"
#define DES_KEY	      "DES"
#define DES3_KEY      "DES3"
#define DSA_SM2_KEY   "DSA_SM2_FP"
#define NIST_KEY      "NIST"
#define SM4_KEY	      "SM4"
#define UNDEFINED_KEY "UNDEFINED"

/* List of hash algo */
#define MD5_ALG	      "MD5"
#define SHA1_ALG      "SHA1"
#define SHA224_ALG    "SHA224"
#define SHA256_ALG    "SHA256"
#define SHA384_ALG    "SHA384"
#define SHA512_ALG    "SHA512"
#define SM3_ALG	      "SM3"
#define UNDEFINED_ALG "UNDEFINED"

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

#endif /* __TYPES_H__ */
