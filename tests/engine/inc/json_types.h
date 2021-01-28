/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __JSON_TYPES_H__
#define __JSON_TYPES_H__

/* List of parameters present in JSON test definition file */
#define ATTR_LIST_OBJ  "attributes_list"
#define CMD_OBJ	       "command"
#define DEPENDS_OBJ    "depends"
#define DIGEST_OBJ     "digest"
#define INPUT_OBJ      "input"
#define KEY_FORMAT_OBJ "format"
#define KEY_ID_OBJ     "key_id"
#define PRIV_KEY_OBJ   "priv_key"
#define PUB_KEY_OBJ    "pub_key"
#define RES_OBJ	       "result"
#define SEC_SIZE_OBJ   "security_size"
#define SUBSYSTEM_OBJ  "subsystem"
#define SUBTEST_OBJ    "subtest "
#define TEST_ERR_OBJ   "test_error"
#define VERSION_OBJ    "version"

#define SUBTEST_OBJ_LEN strlen(SUBTEST_OBJ)

/* SMW API default version. Used if not set in test definition file */
#define SMW_API_DEFAULT_VERSION 0

/* List of commands */
#define DELETE		   "DELETE"
#define EXPORT		   "EXPORT"
#define EXPORT_KEYPAIR	   "EXPORT_KEYPAIR"
#define EXPORT_PRIVATE	   "EXPORT_PRIVATE"
#define EXPORT_PUBLIC	   "EXPORT_PUBLIC"
#define GENERATE	   "GENERATE"
#define GENERATE_AES	   "GENERATE_AES"
#define GENERATE_BR1	   "GENERATE_BR1"
#define GENERATE_BT1	   "GENERATE_BT1"
#define GENERATE_DES	   "GENERATE_DES"
#define GENERATE_DES3	   "GENERATE_DES3"
#define GENERATE_DSA_SM2   "GENERATE_DSA_SM2"
#define GENERATE_NIST	   "GENERATE_NIST"
#define GENERATE_SM4	   "GENERATE_SM4"
#define GENERATE_UNDEFINED "GENERATE_UNDEFINED"
#define HASH		   "HASH"
#define HASH_MD5	   "HASH_MD5"
#define HASH_SHA1	   "HASH_SHA1"
#define HASH_SHA224	   "HASH_SHA224"
#define HASH_SHA256	   "HASH_SHA256"
#define HASH_SHA384	   "HASH_SHA384"
#define HASH_SHA512	   "HASH_SHA512"
#define HASH_SM3	   "HASH_SM3"
#define HASH_UNDEFINED	   "HASH_UNDEFINED"
#define IMPORT		   "IMPORT"
#define IMPORT_AES	   "IMPORT_AES"
#define IMPORT_BR1	   "IMPORT_BR1"
#define IMPORT_BT1	   "IMPORT_BT1"
#define IMPORT_DES	   "IMPORT_DES"
#define IMPORT_DES3	   "IMPORT_DES3"
#define IMPORT_DSA_SM2	   "IMPORT_DSA_SM2"
#define IMPORT_NIST	   "IMPORT_NIST"
#define IMPORT_SM4	   "IMPORT_SM4"
#define IMPORT_UNDEFINED   "IMPORT_UNDEFINED"

/* 'test_error' parameter values */
enum arguments_test_err_case {
	ARGS_NULL = 0,
	BAD_FORMAT,
	BAD_ATTRIBUTES,
	BAD_KEY_SEC_SIZE,
	BAD_KEY_TYPE,
	BAD_VERSION,
	BAD_SUBSYSTEM,
	BAD_ALGO,
	DIGEST_BUFFER_NULL,
	DIGEST_LENGTH_ZERO,
	KEY_BUFFER_NULL,
	KEY_DESC_ID_NOT_SET,
	KEY_DESC_ID_SET,
	KEY_DESC_NULL,
	KEY_TYPE_UNDEFINED,
	NO_BUFFER_SET,
	PRIV_DATA_LEN_NOT_SET,
	PRIV_KEY_BUFF_LEN_SET,
	PRIV_KEY_BUFF_SET,
	PUB_DATA_LEN_NOT_SET,
	PUB_KEY_BUFF_TOO_SMALL,
	WRONG_SECURITY_SIZE,
	WRONG_TYPE_NAME,
	NB_ERROR_CASE,
};

/* Type of export */
enum export_type {
	EXP_KEYPAIR,
	EXP_PRIV,
	EXP_PUB,
};

#endif /* __JSON_TYPES_H__ */
