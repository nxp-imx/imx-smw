/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __OS_MUTEX_H__
#define __OS_MUTEX_H__

#include <pkcs11smw.h>

CK_RV mutex_create_empty(CK_VOID_PTR_PTR mutex);
CK_RV mutex_destroy_empty(CK_VOID_PTR mutex);
CK_RV mutex_lock_empty(CK_VOID_PTR mutex);
CK_RV mutex_unlock_empty(CK_VOID_PTR mutex);

CK_RV mutex_create(CK_VOID_PTR_PTR mutex);
CK_RV mutex_destroy(CK_VOID_PTR mutex);
CK_RV mutex_lock(CK_VOID_PTR mutex);
CK_RV mutex_unlock(CK_VOID_PTR mutex);

#endif /* __OS_MUTEX_H__ */
