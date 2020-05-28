/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __LOCAL_H__
#define __LOCAL_H__

#include "pkcs11smw.h"

/*
 * Definition of the device's mechanism information function prototype
 */
#define FUNC_MECH_INFO(name)                                                   \
	CK_RV(name)(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
#define FUNC_MECH_INFO_PTR(name) FUNC_MECH_INFO(*(name))

FUNC_MECH_INFO(hsm_info_mdigest);
FUNC_MECH_INFO(optee_info_mdigest);

extern const struct libdev hsm_info;
extern const struct libdev optee_info;

#endif /* __LOCAL_H__ */
