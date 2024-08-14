/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */
#ifndef __IFSMW_UTILS_H__
#define __IFSMW_UTILS_H__

#include "smw_status.h"

#include "pkcs11smw.h"

/**
 * smw_status_to_ck_rv() - Converts a SMW status to CK_RV value
 * @status: SMW status
 *
 * return:
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_BUFFER_TOO_SMALL          - Output buffer too small
 * CKR_OK                        - Success
 * CKR_BUFFER_TOO_SMALL          - Output buffer too small
 * CKR_SIGNATURE_INVALID         - Signature is invalid
 * CKR_SIGNATURE_LEN_RANGE       - Signature length is invalid
 */
CK_RV smw_status_to_ck_rv(enum smw_status_code status);

#endif /* __IFSMW_UTILS_H__ */
