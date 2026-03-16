// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "lib_session.h"

CK_RV C_AsyncComplete(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		      CK_ASYNC_DATA_PTR pResult)
{
	(void)hSession;
	(void)pFunctionName;
	(void)pResult;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncGetID(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		   CK_ULONG_PTR pulID)
{
	(void)hSession;
	(void)pFunctionName;
	(void)pulID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		  CK_ULONG ulID, CK_BYTE_PTR pData, CK_ULONG ulData)
{
	(void)hSession;
	(void)pFunctionName;
	(void)ulID;
	(void)pData;
	(void)ulData;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
