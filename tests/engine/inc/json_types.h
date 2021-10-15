/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __JSON_TYPES_H__
#define __JSON_TYPES_H__

/* List of parameters present in JSON test definition file */
#define ALGO_OBJ	  "algo"
#define ATTR_LIST_OBJ	  "attributes_list"
#define CMD_OBJ		  "command"
#define COPY_CIPHER_CTX	  "copy_cipher_ctx"
#define CTX_ID_OBJ	  "context_id"
#define DEPENDS_OBJ	  "depends"
#define DIGEST_OBJ	  "digest"
#define FILEPATH_OBJ	  "filepath"
#define INPUT_OBJ	  "input"
#define IV_OBJ		  "iv"
#define KEY_FORMAT_OBJ	  "format"
#define KEY_ID_OBJ	  "key_id"
#define KEY_TYPE_OBJ	  "key_type"
#define MAC_OBJ		  "mac"
#define MESS_OBJ	  "message"
#define MODE_OBJ	  "mode"
#define MODULUS_OBJ	  "modulus"
#define NB_KEYS_OBJ	  "nb_keys"
#define OP_ARGS_OBJ	  "op_args"
#define OP_INPUT_OBJ	  "op_input"
#define OP_OUTPUT_OBJ	  "op_output"
#define OP_TYPE_OBJ	  "op_type"
#define OUTPUT_OBJ	  "output"
#define PRIV_KEY_OBJ	  "priv_key"
#define PUB_KEY_OBJ	  "pub_key"
#define RANDOM_OBJ	  "random"
#define RES_OBJ		  "result"
#define SAVE_OUT_OBJ	  "save_output"
#define SEC_SIZE_OBJ	  "security_size"
#define SIGN_ID_OBJ	  "sign_id"
#define SIGN_OBJ	  "signature"
#define SUBSYSTEM_OBJ	  "subsystem"
#define SUBSYSTEM_EXP_OBJ "subsystem_exp"
#define SUBTEST_OBJ	  "subtest "
#define TEST_ERR_OBJ	  "test_error"
#define VERSION_OBJ	  "version"

#define SUBTEST_OBJ_LEN strlen(SUBTEST_OBJ)

/* SMW API default version. Used if not set in test definition file */
#define SMW_API_DEFAULT_VERSION 0

/* List of commands */
#define CIPHER		"CIPHER"
#define CIPHER_INIT	"CIPHER_INIT"
#define CIPHER_UPDATE	"CIPHER_UPDATE"
#define CIPHER_FINAL	"CIPHER_FINAL"
#define CONFIG		"CONFIG"
#define CONFIG_LOAD	"CONFIG_LOAD"
#define CONFIG_UNLOAD	"CONFIG_UNLOAD"
#define DELETE		"DELETE"
#define DERIVE		"DERIVE"
#define EXPORT		"EXPORT"
#define EXPORT_KEYPAIR	"EXPORT_KEYPAIR"
#define EXPORT_PRIVATE	"EXPORT_PRIVATE"
#define EXPORT_PUBLIC	"EXPORT_PUBLIC"
#define GENERATE	"GENERATE"
#define GET_VERSION	"GET_VERSION"
#define HASH		"HASH"
#define HMAC		"HMAC"
#define IMPORT		"IMPORT"
#define OP_CTX		"OP_CONTEXT"
#define OP_CTX_CANCEL	"OP_CONTEXT_CANCEL"
#define OP_CTX_COPY	"OP_CONTEXT_COPY"
#define RESTORE_KEY_IDS "RESTORE_KEY_IDS"
#define RNG		"RNG"
#define SAVE_KEY_IDS	"SAVE_KEY_IDS"
#define SIGN		"SIGN"
#define VERIFY		"VERIFY"

/* 'test_error' parameter values */
enum arguments_test_err_case {
	NOT_DEFINED = 0, // Nothing specified in the test definition
	ARGS_NULL,
	BAD_FORMAT,
	KEY_BUFFER_NULL,
	KEY_DESC_ID_NOT_SET,
	KEY_DESC_ID_SET, /* 5 */
	KEY_DESC_NULL,
	KEY_DESC_OUT_NULL,
	NB_ERROR_CASE,
	CIPHER_NO_NB_KEYS,
	CIPHER_NO_KEYS, /* 10 */
	CIPHER_DIFF_SUBSYSTEM,
	CIPHER_DIFF_KEY_TYPE,
	CTX_NULL,
	CTX_HANDLE_NULL,
	DST_CPY_ARGS_NULL, /* 15 */
	TLS12_KDF_ARGS_NULL,
	FAKE_KEY_ID,
};

/* Type of export */
enum export_type {
	EXP_KEYPAIR,
	EXP_PRIV,
	EXP_PUB,
};

#endif /* __JSON_TYPES_H__ */
