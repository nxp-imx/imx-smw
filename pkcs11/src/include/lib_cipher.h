/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __LIB_CIPHER_H__
#define __LIB_CIPHER_H__

#include "lib_opctx.h"

#include "types.h"

/**
 * lib_cipher_ctx - Cipher context
 * @hkey: Operation key handle
 * @cipher_mech: Cipher mechanism
 * @iv: Pointer to initialization vector
 * @iv_length: @iv length in bytes
 * @current_state: Current cipher operation state
 * @context: Pointer to multi-part operation context
 * @key_value: Pointer to Key value
 * @key_len: key value length in bytes
 */
struct lib_cipher_ctx {
	CK_OBJECT_HANDLE hkey;
	CK_MECHANISM_TYPE cipher_mech;
	CK_BYTE_PTR iv;
	CK_ULONG iv_length;
	enum op_state current_state;
	void *context;
	CK_BYTE_PTR key_value;
	CK_ULONG key_len;
};

/**
 * lib_cipher_params - Cipher parameters
 * @op_flag: Operation flag
 * @ctx: Pointer to cipher context
 * @pinput: Pointer to input data buffer
 * @uldatalen: input data buffer length in bytes
 * @poutput: Pointer to output data buffer
 * @output_length: output buffer length in bytes
 * @state: Operation state to be performed
 */
struct lib_cipher_params {
	CK_FLAGS op_flag;
	struct lib_cipher_ctx *ctx;
	CK_BYTE_PTR pinput;
	CK_ULONG input_length;
	CK_BYTE_PTR poutput;
	CK_ULONG output_length;
	enum op_state state;
};

/**
 * lib_encrypt_decrypt_init() - Initialize an encrypt or decrypt operation
 * @hsession: Session handle
 * @pmechanism: Pointer to operation mechanism
 * @hkey: Key handle
 * @op_flag: Operation flag
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined or no context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_SLOT_ID_INVALID                - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT              - Token is not present
 * CKR_MECHANISM_INVALID              - Mechanism not supported
 * CKR_MECHANISM_PARAM_INVALID        - Machanism parameters invalid
 * CKR_KEY_FUNCTION_NOT_PERMITTED     - Function not permitted with @hkey
 * CKR_OPERATION_ACTIVE               - Operation is already initialized
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV lib_encrypt_decrypt_init(CK_SESSION_HANDLE hsession,
			       CK_MECHANISM_PTR pmechanism,
			       CK_OBJECT_HANDLE hkey, CK_FLAGS op_flag);

/**
 * lib_encrypt_decrypt() - Run encryption/decryption operation
 * @hsession: Session handle
 * @pinput: Pointer to input data buffer
 * @input_length: Pointer to input data buffer length in bytes
 * @poutput: Pointer to output data buffer
 * @poutput_length: Pointer to output data buffer length in bytes
 * @op_flag: Operation flag
 * @state: Operation state to be performed
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_BUFFER_TOO_SMALL               - Buffer too small
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_DATA_INVALID                   - Data is invalid
 * CKR_DATA_LEN_RANGE                 - Data length is invalid
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_ENCRYPTED_DATA_INVALID         - Ciphertext is invalid
 * CKR_ENCRYPTED_DATA_LEN_RANGE       - Ciphertext length is invalid
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV lib_encrypt_decrypt(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pinput,
			  CK_ULONG input_length, CK_BYTE_PTR poutput,
			  CK_ULONG_PTR poutput_length, CK_FLAGS op_flag,
			  enum op_state state);

#endif /* __LIB_CIPHER_H__ */
