// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2026 NXP
 */

#include "pkcs11smw.h"

#include "lib_device.h"

/**
 * C_SeedRandom() - Mix additional seed material into the random number
 *                  generator.
 * @hSession: [in] Session handle.
 * @pSeed: [in] Pointer to the seed material.
 * @ulSeedLen: [in] Length of the seed material in bytes.
 *
 * .. note::
 *    This function is not supported by this implementation.
 *
 * Return:
 *  - CKR_RANDOM_SEED_NOT_SUPPORTED:
 *      Function not supported
 */
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	(void)hSession;
	(void)pSeed;
	(void)ulSeedLen;

	return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

/**
 * C_GenerateRandom() - Generate random data.
 * @hSession: [in] Session handle.
 * @pRandomData: [ouit] Pointer to buffer to receive the random data.
 * @ulRandomLen: [in] Length of random data to generate in bytes.
 *
 * This function generates random or pseudo-random data for the specified
 * session.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Invalid session handle.
 *  - CKR_ARGUMENTS_BAD
 *      - The @pRandomData is NULL.
 *      - The @ulRandomLen is 0.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
		       CK_ULONG ulRandomLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pRandomData || !ulRandomLen)
		return CKR_ARGUMENTS_BAD;

	return libdev_rng(hSession, pRandomData, ulRandomLen);
}
