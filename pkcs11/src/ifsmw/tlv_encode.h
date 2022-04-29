/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */
#ifndef __TLV_ENCODE_H__
#define __TLV_ENCODE_H__

#include "libobj_types.h"
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
 * new boolean TLV's string.
 *
 * return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_boolean(struct smw_tlv *tlv, const char *type);

/**
 * tlv_encode_large_numeral() - Add a TLV's large numeral @type to TLV string
 * @tlv: TLV's string to be updated
 * @type: Large numeral string to add
 * @bignum: Bignumber to encode
 *
 * Function encodes a TLV's large numeral of @type and add it to the
 * @tlv's string.
 * If current @tlv's string is too small, reallocate it to contain the
 * new large numeral TLV's string.
 *
 * return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_large_numeral(struct smw_tlv *tlv, const char *type,
			       struct libbignumber *bignum);

/**
 * tlv_encode_string() - Add a TLV's string @type to TLV string
 * @tlv: TLV's string to be updated
 * @type: String data name
 * @value: String value
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_string(struct smw_tlv *tlv, const char *type,
			const char *value);

/**
 * tlv_encode_enum() - Add a TLV's enumeration @type to TLV string
 * @tlv: TLV's string to be updated
 * @type: Enumeration prefix string
 * @value: Enumeration value string
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_enum(struct smw_tlv *tlv, const char *type, const char *value);

/**
 * tlv_encode_numeral() - Add TLV's numeral @type to TLV string
 * @tlv: TLV's string to be updated
 * @type: Numeral data name (string)
 * @num: Numeral value
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_numeral(struct smw_tlv *tlv, const char *type, long long num);

/**
 * tlv_encode_concat_string() - Add a TLV's string and concatenate TLVs
 * @tlv: TLV's string to be updated
 * @type: String data name
 * @value: String value
 * @concat_tlv: String value to concatenate
 *
 * Add to @tlv a string @type with the @value. Then concatenate the
 * @concat_tlv->string to the added TLV and set the TLV's length equal
 * the total length of both string @value and @concat_tlv->string.
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_concat_string(struct smw_tlv *tlv, const char *type,
			       const char *value, struct smw_tlv *concat_tlv);

/**
 * tlv_encode_tlv() - Add a string of TLVs tagged with @type
 * @tlv: TLV's string to be updated
 * @type: String data name
 * @tlv_value: Value of type tlv string
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV tlv_encode_tlv(struct smw_tlv *tlv, const char *type,
		     struct smw_tlv *tlv_value);

/**
 * tlv_encode_free() - Free the TLV's string
 * @tlv: TLV object
 */
void tlv_encode_free(struct smw_tlv *tlv);

#endif /* __TLV_ENCODE_H__ */
