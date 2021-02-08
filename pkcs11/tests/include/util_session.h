/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_SESSION_H__
#define __UTIL_SESSION_H__

#include "local.h"

int util_open_rw_session_cb(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			    CK_NOTIFY callback, CK_VOID_PTR cb_args,
			    CK_SESSION_HANDLE_PTR sess);
int util_open_ro_session_cb(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			    CK_NOTIFY callback, CK_VOID_PTR cb_args,
			    CK_SESSION_HANDLE_PTR sess);
int util_open_rw_session(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			 CK_SESSION_HANDLE_PTR sess);
int util_open_ro_session(CK_FUNCTION_LIST_PTR pfunc, CK_SLOT_ID p11_slot,
			 CK_SESSION_HANDLE_PTR sess);
void util_close_session(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE_PTR sess);

#endif /* __UTIL_SESSION_H__ */
