/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __TYPES_H__
#define __TYPES_H__

#define JSON_SUBTEST	 "Subtest"
#define JSON_SUBTEST_LEN strlen(JSON_SUBTEST)

/* List of args present in test vectors */
#define CMD_OBJ		  "command"
#define VERSION_OBJ	  "version"
#define SUBSYSTEM_OBJ	  "subsystem"
#define KEY_TYPE_OBJ	  "key_type"
#define SEC_SIZE_OBJ	  "security_size"
#define ATTR_LIST_OBJ	  "attributes_list"
#define ATTR_LIST_LEN_OBJ "attributes_list_len"
#define RES_OBJ		  "result"
#define KEY_ID_OBJ	  "key_identifier_id"
#define ALGO_OBJ	  "algo"
#define INPUT_OBJ	  "input"
#define INPUT_LEN_OBJ	  "input_len"
#define DIGEST_OBJ	  "digest"

/* List of commands */
#define GENERATE_CMD "GENERATE"
#define DELETE_CMD   "DELETE"
#define HASH_CMD     "HASH"

#endif /* __TYPES_H__ */
