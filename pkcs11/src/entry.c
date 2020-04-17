// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "pkcs11smw.h"

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	(void)pInitArgs;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	(void)pReserved;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
