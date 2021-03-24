// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"

#include "tlv_encode.h"

static CK_RV tlv_realloc(struct smw_tlv *tlv, size_t length)
{
	if (!tlv->string) {
		tlv->string = malloc(length);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		tlv->length_max = length;
	} else if (tlv->length_max < tlv->length + length) {
		tlv->string = realloc(tlv->string, tlv->length_max + length);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		tlv->length_max += length;
	}

	return CKR_OK;
}

static void set_tlv_type(struct smw_tlv *tlv, const char *type)
{
	/* Add the Type @type to current tlv string */
	memcpy(&tlv->string[tlv->length], type, strlen(type));
	tlv->length += strlen(type);

	/* Set the Type null terminated character */
	tlv->string[tlv->length++] = 0;
}

static void set_tlv_length(struct smw_tlv *tlv, size_t length)
{
	tlv->string[tlv->length++] = GET_BYTE(length, 1);
	tlv->string[tlv->length++] = GET_BYTE(length, 0);
}

CK_RV tlv_encode_boolean(struct smw_tlv *tlv, const char *type)
{
	CK_RV ret;
	size_t len_add;

	/*
	 * Boolean is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes of 0
	 *   - Value is not set
	 */
	len_add = strlen(type) + 3;
	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	set_tlv_type(tlv, type);

	/* Set the 2 bytes of Length = 0 */
	set_tlv_length(tlv, 0);

	return CKR_OK;
}

CK_RV tlv_encode_large_numeral(struct smw_tlv *tlv, const char *type,
			       struct libbignumber *bignum)
{
	CK_RV ret;
	size_t len_add;

	/*
	 * Large numeral is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (numeral byte length)
	 *   - Value = numeral value
	 */
	len_add = strlen(type) + 3 + bignum->length;
	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	set_tlv_type(tlv, type);

	/* Set the 2 bytes of Length */
	set_tlv_length(tlv, bignum->length);

	memcpy(&tlv->string[tlv->length], bignum->value, bignum->length);
	tlv->length += bignum->length;

	return CKR_OK;
}

void tlv_encode_free(struct smw_tlv *tlv)
{
	if (tlv->string)
		free(tlv->string);
}
