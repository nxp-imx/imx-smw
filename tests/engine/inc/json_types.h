/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __JSON_TYPES_H__
#define __JSON_TYPES_H__

/* List of parameters present in JSON test definition file */
#define ATTR_LIST_OBJ	"attributes_list"
#define CMD_OBJ		"command"
#define CTX_ID_OBJ	"context_id"
#define COPY_CIPHER_CTX "copy_cipher_ctx"
#define DEPENDS_OBJ	"depends"
#define DIGEST_OBJ	"digest"
#define INPUT_OBJ	"input"
#define IV_OBJ		"iv"
#define FILEPATH_OBJ	"filepath"
#define KEY_FORMAT_OBJ	"format"
#define KEY_ID_OBJ	"key_id"
#define KEY_TYPE_OBJ	"key_type"
#define MAC_OBJ		"mac"
#define MESS_OBJ	"message"
#define MODULUS_OBJ	"modulus"
#define MODE_OBJ	"mode"
#define NB_KEYS_OBJ	"nb_keys"
#define OP_ARGS_OBJ	"op_args"
#define OP_INPUT_OBJ	"op_input"
#define OP_OUTPUT_OBJ	"op_output"
#define OP_TYPE_OBJ	"op_type"
#define OUTPUT_OBJ	"output"
#define PRIV_KEY_OBJ	"priv_key"
#define PUB_KEY_OBJ	"pub_key"
#define RANDOM_OBJ	"random"
#define RES_OBJ		"result"
#define SAVE_OUT_OBJ	"save_output"
#define SEC_SIZE_OBJ	"security_size"
#define SIGN_ID_OBJ	"sign_id"
#define SIGN_OBJ	"signature"
#define SUBSYSTEM_OBJ	"subsystem"
#define SUBTEST_OBJ	"subtest "
#define TEST_ERR_OBJ	"test_error"
#define VERSION_OBJ	"version"

#define SUBTEST_OBJ_LEN strlen(SUBTEST_OBJ)

/* SMW API default version. Used if not set in test definition file */
#define SMW_API_DEFAULT_VERSION 0

/* List of commands */
#define CIPHER		     "CIPHER"
#define CIPHER_INIT	     "CIPHER_INIT"
#define CIPHER_UPDATE	     "CIPHER_UPDATE"
#define CIPHER_FINAL	     "CIPHER_FINAL"
#define CONFIG		     "CONFIG"
#define CONFIG_LOAD	     "CONFIG_LOAD"
#define CONFIG_UNLOAD	     "CONFIG_UNLOAD"
#define DELETE		     "DELETE"
#define EXPORT		     "EXPORT"
#define EXPORT_KEYPAIR	     "EXPORT_KEYPAIR"
#define EXPORT_PRIVATE	     "EXPORT_PRIVATE"
#define EXPORT_PUBLIC	     "EXPORT_PUBLIC"
#define GENERATE	     "GENERATE"
#define GENERATE_AES	     "GENERATE_AES"
#define GENERATE_BR1	     "GENERATE_BR1"
#define GENERATE_BT1	     "GENERATE_BT1"
#define GENERATE_DES	     "GENERATE_DES"
#define GENERATE_DES3	     "GENERATE_DES3"
#define GENERATE_DSA_SM2     "GENERATE_DSA_SM2"
#define GENERATE_NIST	     "GENERATE_NIST"
#define GENERATE_SM4	     "GENERATE_SM4"
#define GENERATE_HMAC_MD5    "GENERATE_HMAC_MD5"
#define GENERATE_HMAC_SHA1   "GENERATE_HMAC_SHA1"
#define GENERATE_HMAC_SHA224 "GENERATE_HMAC_SHA224"
#define GENERATE_HMAC_SHA256 "GENERATE_HMAC_SHA256"
#define GENERATE_HMAC_SHA384 "GENERATE_HMAC_SHA384"
#define GENERATE_HMAC_SHA512 "GENERATE_HMAC_SHA512"
#define GENERATE_HMAC_SM3    "GENERATE_HMAC_SM3"
#define GENERATE_RSA	     "GENERATE_RSA"
#define GENERATE_UNDEFINED   "GENERATE_UNDEFINED"
#define HASH		     "HASH"
#define HASH_MD5	     "HASH_MD5"
#define HASH_SHA1	     "HASH_SHA1"
#define HASH_SHA224	     "HASH_SHA224"
#define HASH_SHA256	     "HASH_SHA256"
#define HASH_SHA384	     "HASH_SHA384"
#define HASH_SHA512	     "HASH_SHA512"
#define HASH_SM3	     "HASH_SM3"
#define HASH_UNDEFINED	     "HASH_UNDEFINED"
#define HMAC		     "HMAC"
#define HMAC_MD5	     "HMAC_MD5"
#define HMAC_SHA1	     "HMAC_SHA1"
#define HMAC_SHA224	     "HMAC_SHA224"
#define HMAC_SHA256	     "HMAC_SHA256"
#define HMAC_SHA384	     "HMAC_SHA384"
#define HMAC_SHA512	     "HMAC_SHA512"
#define HMAC_SM3	     "HMAC_SM3"
#define HMAC_UNDEFINED	     "HASH_UNDEFINED"
#define IMPORT		     "IMPORT"
#define IMPORT_AES	     "IMPORT_AES"
#define IMPORT_BR1	     "IMPORT_BR1"
#define IMPORT_BT1	     "IMPORT_BT1"
#define IMPORT_DES	     "IMPORT_DES"
#define IMPORT_DES3	     "IMPORT_DES3"
#define IMPORT_DSA_SM2	     "IMPORT_DSA_SM2"
#define IMPORT_NIST	     "IMPORT_NIST"
#define IMPORT_SM4	     "IMPORT_SM4"
#define IMPORT_HMAC_MD5	     "IMPORT_HMAC_MD5"
#define IMPORT_HMAC_SHA1     "IMPORT_HMAC_SHA1"
#define IMPORT_HMAC_SHA224   "IMPORT_HMAC_SHA224"
#define IMPORT_HMAC_SHA256   "IMPORT_HMAC_SHA256"
#define IMPORT_HMAC_SHA384   "IMPORT_HMAC_SHA384"
#define IMPORT_HMAC_SHA512   "IMPORT_HMAC_SHA512"
#define IMPORT_HMAC_SM3	     "IMPORT_HMAC_SM3"
#define IMPORT_RSA	     "IMPORT_RSA"
#define IMPORT_UNDEFINED     "IMPORT_UNDEFINED"
#define OP_CTX		     "OP_CONTEXT"
#define OP_CTX_CANCEL	     "OP_CONTEXT_CANCEL"
#define OP_CTX_COPY	     "OP_CONTEXT_COPY"
#define RNG		     "RNG"
#define SIGN		     "SIGN"
#define SIGN_MD5	     "SIGN_MD5"
#define SIGN_SHA1	     "SIGN_SHA1"
#define SIGN_SHA224	     "SIGN_SHA224"
#define SIGN_SHA256	     "SIGN_SHA256"
#define SIGN_SHA384	     "SIGN_SHA384"
#define SIGN_SHA512	     "SIGN_SHA512"
#define SIGN_SM3	     "SIGN_SM3"
#define SIGN_UNDEFINED	     "SIGN_UNDEFINED"
#define VERIFY		     "VERIFY"
#define VERIFY_MD5	     "VERIFY_MD5"
#define VERIFY_SHA1	     "VERIFY_SHA1"
#define VERIFY_SHA224	     "VERIFY_SHA224"
#define VERIFY_SHA256	     "VERIFY_SHA256"
#define VERIFY_SHA384	     "VERIFY_SHA384"
#define VERIFY_SHA512	     "VERIFY_SHA512"
#define VERIFY_SM3	     "VERIFY_SM3"
#define VERIFY_UNDEFINED     "VERIFY_UNDEFINED"
#define DERIVE		     "DERIVE"

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
