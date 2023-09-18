/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef __JSON_TYPES_H__
#define __JSON_TYPES_H__

/* List of parameters present in JSON test definition file */
#define ALGO_OBJ		  "algo"
#define API_OBJ			  "api"
#define APP_OBJ			  "App"
#define ATTR_LIST_OBJ		  "attributes_list"
#define CLIENT_W_ENC_KEY_NAME_OBJ "client_w_enc_key_name"
#define CLIENT_W_MAC_KEY_NAME_OBJ "client_w_mac_key_name"
#define CMD_OBJ			  "command"
#define COPY_CIPHER_CTX		  "copy_cipher_ctx"
#define CTX_ID_OBJ		  "context_id"
#define DATA_OBJ		  "data"
#define DEPENDS_OBJ		  "depends"
#define DIGEST_OBJ		  "digest"
#define ELE_INFO_OBJ		  "ele_info"
#define ENCRYPT_KEY_NAME_OBJ	  "encrypt_key_name"
#define FILEPATH_OBJ		  "filepath"
#define FORMAT_OBJ		  "format"
#define HASH_OBJ		  "hash"
#define HSM_INFO_OBJ		  "hsm_info"
#define ID_OBJ			  "id"
#define INPUT_OBJ		  "input"
#define IV_OBJ			  "iv"
#define KEYS_OBJ		  "keys"
#define KEY_DATA_OBJ		  "key_data"
#define KEY_DB_OBJ		  "key_db"
#define KEY_NAME_OBJ		  "key_name"
#define LIB_VERSION_OBJ		  "lib_version"
#define LIFECYCLE_OBJ		  "lifecycle"
#define MAC_ID_OBJ		  "mac_id"
#define MAC_OBJ			  "mac"
#define MASTER_SEC_KEY_NAME_OBJ	  "master_sec_key_name"
#define MESS_OBJ		  "message"
#define MODE_OBJ		  "mode"
#define MODULUS_OBJ		  "modulus"
#define OP_ARGS_OBJ		  "op_args"
#define OP_INPUT_OBJ		  "op_input"
#define OP_OUTPUT_OBJ		  "op_output"
#define OP_TYPE_OBJ		  "op_type"
#define OUTPUT_OBJ		  "output"
#define POLICY_OBJ		  "policy"
#define POST_AFTER		  "post_after"
#define POST_BEFORE		  "post_before"
#define POST_TO_AFTER		  "post_to_after"
#define POST_TO_BEFORE		  "post_to_before"
#define PRIVACY_OBJ		  "privacy"
#define PRIV_KEY_OBJ		  "priv_key"
#define PUB_KEY_OBJ		  "pub_key"
#define RANDOM_OBJ		  "random"
#define RESTORE_OBJ		  "restore"
#define RES_OBJ			  "result"
#define SAVE_OUT_OBJ		  "save_output"
#define SECONDS_OBJ		  "seconds"
#define SEC_SIZE_OBJ		  "security_size"
#define SERVER_W_ENC_KEY_NAME_OBJ "server_w_enc_key_name"
#define SERVER_W_MAC_KEY_NAME_OBJ "server_w_mac_key_name"
#define SIGN_ID_OBJ		  "sign_id"
#define SIGN_KEY_NAME_OBJ	  "sign_key_name"
#define SIGN_OBJ		  "signature"
#define SUBSYSTEM_EXP_OBJ	  "subsystem_exp"
#define SUBSYSTEM_OBJ		  "subsystem"
#define SUBTEST_OBJ		  "subtest "
#define TA_UUID			  "ta_uuid"
#define TEE_INFO_OBJ		  "tee_info"
#define TEST_ERR_OBJ		  "test_error"
#define THREAD_OBJ		  "Thread"
#define TYPE_OBJ		  "type"
#define VERSION_OBJ		  "version"
#define WAIT_AFTER		  "wait_after"
#define WAIT_BEFORE		  "wait_before"

#define SUBTEST_OBJ_LEN strlen(SUBTEST_OBJ)

/* SMW API default version. Used if not set in test definition file */
#define SMW_API_DEFAULT_VERSION 0

/* List of commands */
#define CIPHER		     "CIPHER"
#define CIPHER_FINAL	     "CIPHER_FINAL"
#define CIPHER_INIT	     "CIPHER_INIT"
#define CIPHER_UPDATE	     "CIPHER_UPDATE"
#define COMMIT_KEY_STORAGE   "COMMIT_KEY_STORAGE"
#define CONFIG		     "CONFIG"
#define CONFIG_LOAD	     "CONFIG_LOAD"
#define CONFIG_UNLOAD	     "CONFIG_UNLOAD"
#define DELETE		     "DELETE"
#define DERIVE		     "DERIVE"
#define DEVICE		     "DEVICE"
#define DEVICE_ATTESTATION   "DEVICE_ATTESTATION"
#define DEVICE_GET_LIFECYCLE "DEVICE_GET_LIFECYCLE"
#define DEVICE_SET_LIFECYCLE "DEVICE_SET_LIFECYCLE"
#define DEVICE_UUID	     "DEVICE_UUID"
#define EXPORT		     "EXPORT"
#define EXPORT_KEYPAIR	     "EXPORT_KEYPAIR"
#define EXPORT_PRIVATE	     "EXPORT_PRIVATE"
#define EXPORT_PUBLIC	     "EXPORT_PUBLIC"
#define GENERATE	     "GENERATE"
#define GET_KEY_ATTRIBUTES   "GET_KEY_ATTRIBUTES"
#define GET_VERSION	     "GET_VERSION"
#define HASH		     "HASH"
#define HMAC		     "HMAC"
#define IMPORT		     "IMPORT"
#define MAC		     "MAC"
#define MAC_COMPUTE	     "MAC_COMPUTE"
#define MAC_VERIFY	     "MAC_VERIFY"
#define OP_CTX		     "OP_CONTEXT"
#define OP_CTX_CANCEL	     "OP_CONTEXT_CANCEL"
#define OP_CTX_COPY	     "OP_CONTEXT_COPY"
#define RESTORE_KEY_IDS	     "RESTORE_KEY_IDS"
#define RNG		     "RNG"
#define SAVE_KEY_IDS	     "SAVE_KEY_IDS"
#define SIGN		     "SIGN"
#define STORAGE		     "STORAGE"
#define STORAGE_DELETE	     "STORAGE_DELETE"
#define STORAGE_RETRIEVE     "STORAGE_RETRIEVE"
#define STORAGE_STORE	     "STORAGE_STORE"
#define SUSPEND		     "SUSPEND"
#define VERIFY		     "VERIFY"

/* 'test_error' parameter values */
enum arguments_test_err_case {
	NOT_DEFINED = 0, // Nothing specified in the test definition
	ARGS_NULL,
	KEY_BUFFER_NULL,
	KEY_DESC_NULL,
	KEY_DESC_OUT_NULL,
	NB_ERROR_CASE, /* 5 */
	CTX_NULL,
	CTX_HANDLE_NULL,
	DST_CPY_ARGS_NULL,
	TLS12_KDF_ARGS_NULL,
};

/* Type of export */
enum export_type {
	EXP_KEYPAIR,
	EXP_PRIV,
	EXP_PUB,
};

#endif /* __JSON_TYPES_H__ */
