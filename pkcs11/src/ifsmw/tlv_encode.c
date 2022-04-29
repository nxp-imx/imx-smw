// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"

#include "tlv_encode.h"

#define TLV_LENGTH_SIZE 2

static CK_RV tlv_realloc(struct smw_tlv *tlv, size_t length)
{
	size_t add_length;

	add_length = tlv->length_max - tlv->length + length;

	if (!tlv->string) {
		tlv->string = malloc(length);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		tlv->length_max = length;
	} else if (add_length) {
		tlv->string =
			realloc(tlv->string, tlv->length_max + add_length);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		tlv->length_max += add_length;
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

static void set_tlv_value(struct smw_tlv *tlv, const void *value,
			  size_t value_len)
{
	memcpy(&tlv->string[tlv->length], value, value_len);
	tlv->length += value_len;
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
	len_add = strlen(type) + 1 + TLV_LENGTH_SIZE;
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
	len_add = strlen(type) + 1 + TLV_LENGTH_SIZE + bignum->length;
	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	set_tlv_type(tlv, type);

	/* Set the 2 bytes of Length */
	set_tlv_length(tlv, bignum->length);

	/* Set value */
	set_tlv_value(tlv, bignum->value, bignum->length);

	return CKR_OK;
}

CK_RV tlv_encode_string(struct smw_tlv *tlv, const char *type,
			const char *value)
{
	CK_RV ret;
	size_t len_add;
	size_t value_length = strlen(value) + 1;

	/*
	 * String is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (@value length, null character included)
	 *   - Value = null terminated string @value
	 */

	len_add = strlen(type) + 1 + TLV_LENGTH_SIZE + value_length;
	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	set_tlv_type(tlv, type);

	/* Set length */
	set_tlv_length(tlv, value_length);

	/* Set value */
	set_tlv_value(tlv, value, value_length);

	return CKR_OK;
}

CK_RV tlv_encode_enum(struct smw_tlv *tlv, const char *type, const char *value)
{
	/*
	 * Enumeration is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (@value length, null character included)
	 *   - Value = null terminated string @value
	 */

	return tlv_encode_string(tlv, type, value);
}

CK_RV tlv_encode_numeral(struct smw_tlv *tlv, const char *type, long long num)
{
	CK_RV ret;
	size_t len_add;
	int i;
	unsigned int nb_bytes;

	/* Get number of bytes needed to store @num */
	if (num >> 32)
		nb_bytes = 8;
	else if (num >> 16)
		nb_bytes = 4;
	else if (num >> 8)
		nb_bytes = 2;
	else
		nb_bytes = 1;

	len_add = strlen(type) + 3 + nb_bytes;
	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	set_tlv_type(tlv, type);

	/* Set length */
	set_tlv_length(tlv, nb_bytes);

	for (i = nb_bytes - 1; i >= 0; i--)
		tlv->string[tlv->length++] = GET_BYTE(num, i);

	return CKR_OK;
}

CK_RV tlv_encode_concat_string(struct smw_tlv *tlv, const char *type,
			       const char *value, struct smw_tlv *concat_tlv)
{
	CK_RV ret;
	size_t len_add;
	size_t value_length = strlen(value) + 1;
	size_t tlv_length;

	/*
	 * Concat string is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (@value length, null character included) +
	 *              length of the string value to concatenate
	 *   - Value = null terminated string @value
	 *   - String value to add after field Value
	 */

	len_add = strlen(type) + 1 + TLV_LENGTH_SIZE + value_length;
	tlv_length = value_length + concat_tlv->length_max;
	ret = tlv_realloc(tlv, len_add + concat_tlv->length_max);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	set_tlv_type(tlv, type);

	/* Set length */
	set_tlv_length(tlv, tlv_length);

	/* Set value - Input @value */
	set_tlv_value(tlv, value, value_length);

	/* Concatenate the string value */
	if (concat_tlv->string)
		set_tlv_value(tlv, concat_tlv->string, concat_tlv->length_max);

	return CKR_OK;
}

CK_RV tlv_encode_tlv(struct smw_tlv *tlv, const char *type,
		     struct smw_tlv *tlv_value)
{
	CK_RV ret;
	size_t len_add;

	/*
	 * Build a TLV of TLV is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (@tlv_value->length_max)
	 *   - Value = @tlv_value->string
	 */

	len_add = strlen(type) + 1 + TLV_LENGTH_SIZE;
	ret = tlv_realloc(tlv, len_add + tlv_value->length_max);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	set_tlv_type(tlv, type);

	/* Set length */
	set_tlv_length(tlv, tlv_value->length_max);

	/* Concatenate the string value */
	if (tlv_value->string)
		set_tlv_value(tlv, tlv_value->string, tlv_value->length_max);

	return CKR_OK;
}

void tlv_encode_free(struct smw_tlv *tlv)
{
	if (tlv->string)
		free(tlv->string);

	tlv->string = NULL;
	tlv->length = 0;
	tlv->length_max = 0;
}
