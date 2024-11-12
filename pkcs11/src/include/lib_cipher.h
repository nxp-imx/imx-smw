/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
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
 * @aad: Pointer to additional data
 * @aad_length: @aad length in bytes
 * @payload_length: length of plaintext
 * @tag: Pointer to tag data
 * @tag_length: @tag length in bytes
 * @fixed_iv_length: fixed iv part length
 */
struct lib_cipher_ctx {
	CK_OBJECT_HANDLE hkey;
	CK_MECHANISM_TYPE cipher_mech;
	CK_BYTE_PTR iv;
	CK_ULONG iv_length;
	enum op_state current_state;
	void *context;
	/* Specific AES XTS context members */
	CK_BYTE_PTR key_value;
	CK_ULONG key_len;
	/* Specific AEAD context members */
	CK_BYTE_PTR aad;
	CK_ULONG aad_length;
	CK_ULONG payload_length;
	CK_BYTE_PTR tag;
	CK_ULONG tag_length;
	CK_ULONG fixed_iv_length;
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
 * lib_cipher_cancel_operation() - Cancel the multi-part cipher operation,
 * if active
 * @hsession: Session handle
 * @op_flag: Operation flag
 *
 * Check if any multi-part cipher operation is active.
 * If a multi-part operation is active, cancel the operation
 * and remove the operation context.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_DEVICE_ERROR                   - Device failure
 * CKR_OK                             - Success
 */
CK_RV lib_cipher_cancel_operation(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag);

/**
 * lib_cipher_copy_operation() - Create a copy of the multi-part cipher
 * operation, if active
 * @src: The source context
 * @dst: The destination context
 *
 * Check if any multi-part cipher operation is active.
 * If a multi-part operation is active, copy the operation
 * context into @dst.
 *
 * Return:
 * CKR_STATE_UNSAVEABLE               - State cannot be saved
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_FUNCTION_FAILED                - Operation failed
 * CKR_OBJECT_HANDLE_INVALID          - Object not found
 * CKR_DEVICE_ERROR                   - Device failure
 * CKR_OK                             - Success
 */
CK_RV lib_cipher_copy_operation(void *src, void **dst);

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
 * lib_encrypt_decrypt_reset() - Reset encryption/decryption operation
 * @hsession: Session handle
 * @pparameter: Pointer to parameter
 * @ulparameterlen: @pparameter length in bytes
 * @pAssociatedData: Pointer to optional AAD
 * @ulAssociatedDataLen: @pAssociatedData length in bytes
 * @op_flag: Operation flag
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV lib_encrypt_decrypt_reset(CK_SESSION_HANDLE hsession,
				CK_VOID_PTR pparameter, CK_ULONG ulparameterlen,
				CK_BYTE_PTR pAssociatedData,
				CK_ULONG ulAssociatedDataLen, CK_FLAGS op_flag);

/**
 * lib_encrypt_decrypt() - Run encryption/decryption operation
 * @hsession: Session handle
 * @pparameter: Pointer to parameter
 * @ulparameterlen: @pparameter length in bytes
 * @pAssociatedData: Pointer to optional AAD
 * @ulAssociatedDataLen: @pAssociatedData length in bytes
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
CK_RV lib_encrypt_decrypt(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
			  CK_ULONG ulparameterlen, CK_BYTE_PTR pAssociatedData,
			  CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pinput,
			  CK_ULONG input_length, CK_BYTE_PTR poutput,
			  CK_ULONG_PTR poutput_length, CK_FLAGS op_flag,
			  enum op_state state);

#endif /* __LIB_CIPHER_H__ */
