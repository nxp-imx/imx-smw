/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023-2025 NXP
 */
#ifndef __LIB_SESSION_H__
#define __LIB_SESSION_H__

#include "types.h"

/**
 * struct lib_op_state - operation states backup
 * @op_ctx_count: Number of operation context
 * @obj_count: Number of object recorded in the find query
 * @op_ctx: Array of operation contexts
 * @obj_handle: Array of object handle in the query
 *
 * @op_ctx is NULL, if @op_ctx_count = 0.
 * @obj_handle is NULL, if @obj_count = 0.
 */
struct lib_op_state {
	CK_ULONG op_ctx_count;
	CK_ULONG obj_count;
	struct libopctx *op_ctx;
	CK_OBJECT_HANDLE_PTR obj_handle;
};

/**
 * libsess_open() - Open a session on a token
 * @slotid: Slot ID
 * @flags: Session type to open
 * @application: Reference to the application to notify
 * @notify: Address of the notification function
 * @hsession: Session handle
 *
 * Function verifies that a new session can be opened to the token
 * and if type of the session is supported on this token.
 * If all check flags are green, a new session is created and the
 * handle is returned into @hsession.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT         - Slot ID is not present
 * CKR_TOKEN_WRITE_PROTECTED     - Token is write protected
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
CK_RV libsess_open(CK_SLOT_ID slotid, CK_FLAGS flags, CK_VOID_PTR application,
		   CK_NOTIFY notify, CK_SESSION_HANDLE_PTR hsession);

/**
 * libsess_close() - Close a session
 * @hsession: Session handle
 *
 * Function verifies that the session handler is known and then close the
 * corresponding session.
 * All objects linked to this session are destroyed before closing the session.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Success
 */
CK_RV libsess_close(CK_SESSION_HANDLE hsession);

/**
 * libsess_close_all() - Close all sessions of @slotid token
 * @slotid: Token ID
 *
 * Function closes all sessions of the @slotid token. All token's objects
 * are destroyed.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_OK                        - Success
 */
CK_RV libsess_close_all(CK_SLOT_ID slotid);

/**
 * libsess_get_info() - Get the session information
 * @hsession: Session handle
 * @pinfo: Session information
 *
 * Function verifies that the session handler is known and then returns
 * the session information corresponding.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Success
 */
CK_RV libsess_get_info(CK_SESSION_HANDLE hsession, CK_SESSION_INFO_PTR pinfo);

/**
 * libsess_login() - Loging as @user to the token of the session
 * @hsession: Session handle
 * @user: Cryptoki's user
 *
 * First verifies that the session handler is known.
 * Then try to log on the session's token, if the token is not already
 * logged in and if user can log in.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_USER_ALREADY_LOGGED_IN         - User already logged in
 * CKR_USER_ANOTHER_ALREADY_LOGGED_IN - Another User is already logged
 * CKR_SESSION_READ_ONLY_EXISTS       - SO can't log because R/O session opened
 * CKR_OK                             - Success
 */
CK_RV libsess_login(CK_SESSION_HANDLE hsession, CK_USER_TYPE user);

/**
 * libsess_logout() - Logout of the token of the session
 * @hsession: Session handle
 *
 * Verifies that the session handler is known and then logout.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_logout(CK_SESSION_HANDLE hsession);

/**
 * libsess_get_user() - Get the user logged on the session
 * @hsession: Session handle
 * @user: Cryptoki's user
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_get_user(CK_SESSION_HANDLE hsession, CK_USER_TYPE *user);

/**
 * libsess_validate() - Check the session handle
 * @hsession: Session handle
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_validate(CK_SESSION_HANDLE hsession);

/**
 * libsess_validate_mechanism() - Validate a session mechanism
 * @hsession: Session handle
 * @mech: Mechanism definition
 * @op_flag: Operation flag
 *
 * Checks if the slot id linked to the session supports the mechanism
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_SLOT_ID_INVALID                - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT              - Token is not present
 * CKR_MECHANISM_INVALID              - Mechanism not supported
 * CKR_OK                             - Success
 */
CK_RV libsess_validate_mechanism(CK_SESSION_HANDLE hsession,
				 CK_MECHANISM_PTR mech, CK_FLAGS op_flag);

/**
 * libsess_get_slotid() - Get the Session's slot ID
 * @hsession: Session handle
 * @slotid: Session's slot ID
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - General error
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_get_slotid(CK_SESSION_HANDLE hsession, CK_SLOT_ID_PTR slotid);

/**
 * libsess_get_device() - Get the Session's device (aka token)
 * @hsession: Session handle
 * @dev: Session's device
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_get_device(CK_SESSION_HANDLE hsession, struct libdevice **dev);

/**
 * libsess_get_objects() - Get the session objects list
 * @hsession: Session handle
 * @list: Session objects list
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_get_objects(CK_SESSION_HANDLE hsession,
			  struct libobj_list **list);

/**
 * libsess_set_query() - Set the session query object
 * @hsession: Session handle
 * @query: Session query
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_set_query(CK_SESSION_HANDLE hsession, struct libobj_query *query);

/**
 * libsess_get_query() - Get the session query object
 * @hsession: Session handle
 * @query: Session query
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_get_query(CK_SESSION_HANDLE hsession,
			struct libobj_query **query);

/**
 * libsess_destroy_query() - Destroy the session query object
 * @hsession: Session handle
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_destroy_query(CK_SESSION_HANDLE hsession);

/**
 * libsess_callback() - Call the application callback function
 * @hsession: Session handle
 * @event: Type of notification callback
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_FUNCTION_CANCELED              - Function must be canceled
 * CKR_OK                             - Success
 */
CK_RV libsess_callback(CK_SESSION_HANDLE hsession, CK_NOTIFICATION event);

/**
 * libsess_add_opctx() - Add an active operation in session
 * @hsession: Session handle
 * @op_flag: Operation flag
 * @mech: Mechanism definition
 * @ctx: Operation context
 * @cancel_operation: Pointer to cancel operation function
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OPERATION_ACTIVE               - Operation is already initialized
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV libsess_add_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag,
			CK_MECHANISM_PTR mech, void *ctx,
			CK_RV (*cancel_operation)(void *container,
						  struct libopctx *opctx));

/**
 * libsess_find_opctx() - Find an active session operation
 * @hsession: Session handle
 * @op_flag: Operation flag
 * @mech: Mechanism definition
 * @ctx: Operation context
 *
 * If the operation mechanism @op_flag is present in the list,
 * returns the mechanism parameters in @mech and the operation
 * context in the @ctx.
 * Else return CKR_OPERATION_NOT_INITIALIZED error.

 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_OK                             - Success
 */
CK_RV libsess_find_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag,
			 CK_MECHANISM_PTR mech, void **ctx);

/**
 * libsess_remove_opctx() - Remove an active session operation
 * @hsession: Session handle
 * @op_flag: Operation flag
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_OK                             - Success
 */
CK_RV libsess_remove_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag);

/**
 * libsess_cancel_opctx() - Cancel an on-going multipart operation
 * @hsession: Session handle
 * @op_flag: Operation flag
 * @context: Pointer to multi-part operation context
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_DEVICE_ERROR	                  - Device failure
 * CKR_OK                             - Success
 */
CK_RV libsess_cancel_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag,
			   void **context);

/**
 * libsess_get_operation_state() - Obtain a copy of the cryptographic operations
 * state, if any
 * @hSession: Session handle
 * @pOperationState: Buffer that receives the state
 * @pulOperationStateLen: Length of buffer that receives the state
 *
 * The memory pointed to by @pOperationState is a serialized representation
 * of the session's state. It includes:
 *   - The number of operation context of all active multi-part operations.
 *   - The operation context for each active operation (represented by
 *     struct libopctx).
 *   - The number of objects matching the current active search criteria.
 *   - The object handles of each matching object (CK_OBJECT_HANDLE).
 *
 * Captures the session's cryptographic operation and search state into
 * @pOperationState, allowing it to be restored later via C_SetOperationState(),
 * using libsess_set_operation_state().
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_BUFFER_TOO_SMALL               - Output buffer too small
 * CKR_STATE_UNSAVEABLE               - State cannot be saved
 * CKR_OK                             - Success
 */
CK_RV libsess_get_operation_state(CK_SESSION_HANDLE hSession,
				  CK_BYTE_PTR pOperationState,
				  CK_ULONG_PTR pulOperationStateLen);

/**
 * libsess_set_operation_state() - Restore the cryptographic operations state
 * @hSession: Session handle
 * @pOperationState: Buffer that holds the state
 * @pulOperationStateLen: Length of buffer that holds the state
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_SAVED_STATE_INVALID            - The saved state is not valid
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_KEY_NOT_NEEDED                 - An extraneous key was supplied
 * CKR_OPERATION_ACTIVE               - Operation is already initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_OK                             - Success
 */
CK_RV libsess_set_operation_state(CK_SESSION_HANDLE hSession,
				  CK_BYTE_PTR pOperationState,
				  CK_ULONG ulOperationStateLen);

#endif /* __LIB_SESSION_H__ */
