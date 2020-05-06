/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
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

#endif /* __PKCS11SMW_H__ */
