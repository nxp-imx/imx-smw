// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "pkcs11smw.h"

#include "lib_device.h"

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	(void)hSession;
	(void)pSeed;
	(void)ulSeedLen;

	return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
		       CK_ULONG ulRandomLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pRandomData || !ulRandomLen)
		return CKR_ARGUMENTS_BAD;

	return libdev_rng(hSession, pRandomData, ulRandomLen);
}
