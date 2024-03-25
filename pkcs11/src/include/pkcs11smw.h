/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020, 2024 NXP
 */

#ifndef __PKCS11SMW_H__
#define __PKCS11SMW_H__

#include <stdbool.h>
#include <stddef.h>

/*
 * Define the platform-specific macros required by the pkcs11 headers
 * (refer to pkcs11.h)
 * Those macros must be defined before including the pkcs11.h
 */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name)                                  \
	returnType __attribute__((visibility("default"))) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name)	      returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#include <pkcs11.h>

/*
 * SMW vendor extensions
*/
#define CKK_VENDOR_SMW (CKK_VENDOR_DEFINED | 0x534D57UL)
#define CKM_VENDOR_SMW (CKM_VENDOR_DEFINED | 0x534D57UL)

/* Key type SM4 */
#define CKK_SM4 (CKK_VENDOR_SMW + 1)

/* SM4 mechanisms */
#define CKM_SM4_KEY_GEN (CKM_VENDOR_SMW + 1)
#define CKM_SM4_CBC	(CKM_VENDOR_SMW + 2)
#define CKM_SM4_CTR	(CKM_VENDOR_SMW + 3)
#define CKM_SM4_ECB	(CKM_VENDOR_SMW + 4)

/* Parameters for SM4-CTR mechanism: same as AES-CTR */
typedef struct CK_AES_CTR_PARAMS CK_SM4_CTR_PARAMS;

typedef CK_SM4_CTR_PARAMS CK_PTR CK_SM4_CTR_PARAMS_PTR;

#endif /* __PKCS11SMW_H__ */
