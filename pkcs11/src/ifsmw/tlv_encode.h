/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __TLV_ENCODE_H__
#define __TLV_ENCODE_H__

#include "pkcs11smw.h"

struct smw_tlv {
	char *string;		 // Encoded SMW's TLV string
	unsigned int length;	 // Length of the SMW's TLV string
	unsigned int length_max; // Maximum length of the @string allocated
};

/**
 * tlv_encode_boolean() - Add a TLV's boolean @type to TLV string
 * @tlv: TLV's string to be updated
 * @type: Boolean string to add
 *
 * Function encodes a TLV's boolean of @type and add it to the
 * @tlv's string.
 * If current @tlv's string is too small, reallocate it to contain the
 * new boolean TLS's string.
 *
 * return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_boolean(struct smw_tlv *tlv, const char *type);

/**
 * tlv_encode_free() - Free the TLV's string
 * @tlv: TLV object
 */
void tlv_encode_free(struct smw_tlv *tlv);

#endif /* __TLV_ENCODE_H__ */
