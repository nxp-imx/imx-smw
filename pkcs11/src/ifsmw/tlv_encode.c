// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"

#include "tlv_encode.h"

#define TLV_LENGTH_SIZE 2

static size_t tlv_string_size(const char *type, size_t value_length)
{
	size_t size = 0;

	size = strlen(type);
	if (!INC_OVERFLOW(size, 1) && !INC_OVERFLOW(size, TLV_LENGTH_SIZE) &&
	    !INC_OVERFLOW(size, value_length))
		return size;

	return 0;
}

static CK_RV tlv_realloc(struct smw_tlv *tlv, size_t length)
{
	size_t add_length = 0;

	if (SUB_OVERFLOW(tlv->length_max, tlv->length, &add_length))
		return CKR_ARGUMENTS_BAD;

	if (INC_OVERFLOW(add_length, length))
		return CKR_ARGUMENTS_BAD;

	if (!tlv->string) {
		tlv->string = malloc(length);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		if (SET_OVERFLOW(length, tlv->length_max)) {
			free(tlv->string);
			tlv->string = NULL;
			return CKR_ARGUMENTS_BAD;
		}
	} else if (add_length) {
		tlv->string =
			realloc(tlv->string, tlv->length_max + add_length);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		tlv->length_max += add_length;
	}

	return CKR_OK;
}

static CK_RV set_tlv_type(struct smw_tlv *tlv, const char *type)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t length = 0;
	unsigned int index = tlv->length;

	length = strlen(type) + 1;

	if (!INC_OVERFLOW(tlv->length, length)) {
		/* Add the Type @type to current tlv string */
		memcpy(&tlv->string[index], type, length);

		ret = CKR_OK;
	}

	return ret;
}

static CK_RV set_tlv_length(struct smw_tlv *tlv, size_t length)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	uint8_t byte = 0;
	char *tlv_string = &tlv->string[tlv->length];

	if (!INC_OVERFLOW(tlv->length, 2)) {
		byte = GET_BYTE(length, 1);
		(void)SET_OVERFLOW(byte, *tlv_string);

		byte = GET_BYTE(length, 0);
		(void)SET_OVERFLOW(byte, *(++tlv_string));

		ret = CKR_OK;
	}

	return ret;
}

static CK_RV set_tlv_value(struct smw_tlv *tlv, const void *value,
			   size_t value_len)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	unsigned int index = tlv->length;

	if (!INC_OVERFLOW(tlv->length, value_len)) {
		memcpy(&tlv->string[index], value, value_len);
		ret = CKR_OK;
	}

	return ret;
}

CK_RV tlv_encode_boolean(struct smw_tlv *tlv, const char *type)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t len_add = 0;

	/*
	 * Boolean is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes of 0
	 *   - Value is not set
	 */
	len_add = tlv_string_size(type, 0);
	if (!len_add)
		return ret;

	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	ret = set_tlv_type(tlv, type);
	if (ret == CKR_OK)
		/* Set the 2 bytes of Length = 0 */
		ret = set_tlv_length(tlv, 0);

	return ret;
}

CK_RV tlv_encode_large_numeral(struct smw_tlv *tlv, const char *type,
			       struct libbignumber *bignum)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t len_add = 0;

	/*
	 * Large numeral is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (numeral byte length)
	 *   - Value = numeral value
	 */
	len_add = tlv_string_size(type, bignum->length);
	if (!len_add)
		return ret;

	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	ret = set_tlv_type(tlv, type);
	if (ret != CKR_OK)
		return ret;

	/* Set the 2 bytes of Length */
	ret = set_tlv_length(tlv, bignum->length);
	if (ret == CKR_OK)
		/* Set value */
		ret = set_tlv_value(tlv, bignum->value, bignum->length);

	return ret;
}

CK_RV tlv_encode_string(struct smw_tlv *tlv, const char *type,
			const char *value)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t len_add = 0;
	size_t value_length = 0;

	/*
	 * String is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (@value length, null character included)
	 *   - Value = null terminated string @value
	 */
	value_length = strlen(value);
	if (INC_OVERFLOW(value_length, 1))
		return ret;

	len_add = tlv_string_size(type, value_length);
	if (!len_add)
		return ret;

	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	ret = set_tlv_type(tlv, type);
	if (ret != CKR_OK)
		return ret;

	/* Set length */
	ret = set_tlv_length(tlv, value_length);
	if (ret == CKR_OK)
		/* Set value */
		ret = set_tlv_value(tlv, value, value_length);

	return ret;
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
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t len_add = 0;
	unsigned int nb_bytes = 0;
	uint8_t byte = 0;

	/* Get number of bytes needed to store @num */
	if (num >> 32)
		nb_bytes = 8;
	else if (num >> 16)
		nb_bytes = 4;
	else if (num >> 8)
		nb_bytes = 2;
	else
		nb_bytes = 1;

	len_add = tlv_string_size(type, nb_bytes);
	if (!len_add)
		return ret;

	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	ret = set_tlv_type(tlv, type);
	if (ret != CKR_OK)
		return ret;

	/* Set length */
	ret = set_tlv_length(tlv, nb_bytes);
	if (ret != CKR_OK)
		return ret;

	for (; nb_bytes; nb_bytes--) {
		byte = GET_BYTE(num, nb_bytes - 1);
		(void)SET_OVERFLOW(byte, tlv->string[tlv->length]);

		if (INC_OVERFLOW(tlv->length, 1)) {
			ret = CKR_ARGUMENTS_BAD;
			break;
		}
	}

	return ret;
}

CK_RV tlv_encode_concat_string(struct smw_tlv *tlv, const char *type,
			       const char *value, struct smw_tlv *concat_tlv)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t len_add = 0;
	size_t value_length = 0;
	size_t tlv_length = 0;

	/*
	 * Concat string is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (@value length, null character included) +
	 *              length of the string value to concatenate
	 *   - Value = null terminated string @value
	 *   - String value to add after field Value
	 */

	value_length = strlen(value);
	if (INC_OVERFLOW(value_length, 1))
		return ret;

	len_add = tlv_string_size(type, value_length);
	if (!len_add)
		return ret;

	if (INC_OVERFLOW(len_add, concat_tlv->length_max))
		return ret;

	if (ADD_OVERFLOW(value_length, concat_tlv->length_max, &tlv_length))
		return ret;

	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	ret = set_tlv_type(tlv, type);
	if (ret != CKR_OK)
		return ret;

	/* Set length */
	ret = set_tlv_length(tlv, tlv_length);
	if (ret != CKR_OK)
		return ret;

	/* Set value - Input @value */
	ret = set_tlv_value(tlv, value, value_length);

	/* Concatenate the string value */
	if (ret == CKR_OK && concat_tlv->string)
		ret = set_tlv_value(tlv, concat_tlv->string,
				    concat_tlv->length_max);

	return ret;
}

CK_RV tlv_encode_tlv(struct smw_tlv *tlv, const char *type,
		     struct smw_tlv *tlv_value)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t len_add = 0;

	/*
	 * Build a TLV of TLV is TLV encoded with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes (@tlv_value->length_max)
	 *   - Value = @tlv_value->string
	 */

	len_add = tlv_string_size(type, tlv_value->length_max);
	if (!len_add)
		return ret;

	ret = tlv_realloc(tlv, len_add);
	if (ret != CKR_OK)
		return ret;

	/* Set type */
	ret = set_tlv_type(tlv, type);
	if (ret != CKR_OK)
		return ret;

	/* Set length */
	ret = set_tlv_length(tlv, tlv_value->length_max);

	/* Concatenate the string value */
	if (ret == CKR_OK && tlv_value->string)
		ret = set_tlv_value(tlv, tlv_value->string,
				    tlv_value->length_max);

	return ret;
}

void tlv_encode_free(struct smw_tlv *tlv)
{
	if (tlv->string)
		free(tlv->string);

	tlv->string = NULL;
	tlv->length = 0;
	tlv->length_max = 0;
}
