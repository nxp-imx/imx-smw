// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "json_types.h"
#include "types.h"
#include "util.h"
#include "util_tlv.h"

struct tlv {
	const char *type;
	int length;
	enum json_type val_type;
	union {
		long num;
		const char *str;
	} value;
};

static int get_tlv_numeral_byte(long value)
{
	long val = value;
	int nb_bytes = 0;

	do {
		nb_bytes++;
		val >>= CHAR_BIT;
	} while (val);

	if (nb_bytes > 1) {
		if (nb_bytes > 4)
			nb_bytes = 8;
		else if (nb_bytes > 2)
			nb_bytes = 4;
	}

	return nb_bytes;
}

static int read_tlv(struct tlv *tlv, unsigned int *len, json_object *obj)
{
	int ret = ERR_CODE(FAILED);
	int nb_elem = 0;
	json_object *ovalue;

	nb_elem = json_object_array_length(obj);
	DBG_PRINT("Get nb array elem %d", nb_elem);

	tlv->type = json_object_get_string(json_object_array_get_idx(obj, 0));
	/* Add length of the 'type" null terminated string */
	*len += strlen(tlv->type) + 1;

	/* Add length of the 'length' always 2 bytes, regardless 'value' */
	*len += 2;

	/* Initialize tlv->length to 0 */
	tlv->length = 0;

	if (nb_elem > 1) {
		ovalue = json_object_array_get_idx(obj, 1);

		tlv->val_type = json_object_get_type(ovalue);

		switch (tlv->val_type) {
		case json_type_int:
			tlv->value.num = json_object_get_int64(ovalue);
			/* Number of bytes used to code the value */
			tlv->length = get_tlv_numeral_byte(tlv->value.num);
			DBG_PRINT("Type %s, L=%d, V=%ld", tlv->type,
				  tlv->length, tlv->value.num);
			ret = ERR_CODE(PASSED);
			break;

		case json_type_string:
			tlv->value.str = json_object_get_string(ovalue);
			/* Length is the string length in including the NULL */
			tlv->length = strlen(tlv->value.str) + 1;
			DBG_PRINT("Type %s, L=%d, V=%s", tlv->type, tlv->length,
				  tlv->value.str);
			ret = ERR_CODE(PASSED);
			break;

		default:
			DBG_PRINT("TLV Value of type %d not supported",
				  tlv->val_type);
			break;
		}
	} else {
		DBG_PRINT("Type %s, L=%d", tlv->type, tlv->length);
		tlv->val_type = json_type_boolean;
		ret = ERR_CODE(PASSED);
	}

	/*
	 * Add length of the 'value' defined by tlv->length
	 * If no value, tlv->length is 0.
	 */
	*len += tlv->length;
	return ret;
}

static int build_attr_lists(unsigned char **attr, unsigned int len,
			    struct tlv *tlv, int nb_tlv)
{
	int ret;
	int idx;
	unsigned char *attr_string = NULL;

	attr_string = malloc(len);
	if (!attr_string)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	*attr = attr_string;

	/* Build the attributes list with all tlv(s) read */
	for (idx = 0; idx < nb_tlv; idx++) {
		/* Copy the 'type' of TLV */
		memcpy(attr_string, tlv[idx].type, strlen(tlv[idx].type));
		attr_string += strlen(tlv[idx].type);
		/* Add the NULL termination */
		*(attr_string++) = '\0';

		/* Set the 'length' of TLV with 2 bytes */
		*(attr_string++) = tlv[idx].length >> CHAR_BIT;
		*(attr_string++) = tlv[idx].length & UCHAR_MAX;

		/* Copy the 'value' of TLV */
		switch (tlv[idx].val_type) {
		case json_type_int:
			for (int nb_bytes = tlv[idx].length; nb_bytes;
			     nb_bytes--) {
				*(attr_string++) =
					UCHAR_SHIFT_BYTE(tlv[idx].value.num,
							 nb_bytes - 1);
			}
			break;

		case json_type_string:
			memcpy(attr_string, tlv[idx].value.str,
			       tlv[idx].length);
			break;

		case json_type_boolean:
			break;

		default:
			DBG_PRINT("Unsupported TLV of type %d",
				  tlv[idx].val_type);
			ret = ERR_CODE(FAILED);
			goto end;
		}

		attr_string += tlv[idx].length;
	}

	ret = ERR_CODE(PASSED);

end:
	if (ret != ERR_CODE(PASSED)) {
		free(*attr);
		*attr = NULL;
	}

	return ret;
}

int util_tlv_read_attrs(unsigned char **attr, unsigned int *len,
			json_object *params)
{
	int ret;
	struct tlv *tlv = NULL;
	json_object *oattr_list;
	json_object *oattr;
	int nb_attrs = 0;
	int idx;

	if (!params || !attr || !len) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	*attr = NULL;
	*len = 0;
	ret = ERR_CODE(PASSED);

	if (json_object_object_get_ex(params, ATTR_LIST_OBJ, &oattr_list)) {
		if (json_object_get_type(oattr_list) != json_type_array) {
			DBG_PRINT("Attributes must be json-c array(s)");
			return ERR_CODE(FAILED);
		}

		nb_attrs = json_object_array_length(oattr_list);
		DBG_PRINT("Get nb array attr %d", nb_attrs);

		/* Check if this is an array of array or just one attribute */
		oattr = json_object_array_get_idx(oattr_list, 0);
		if (json_object_get_type(oattr) != json_type_array) {
			nb_attrs = 1;

			/* There is only one attribute to read */
			oattr = oattr_list;
		}

		tlv = calloc(1, nb_attrs * sizeof(*tlv));
		if (!tlv)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		for (idx = 0; idx < nb_attrs; idx++) {
			if (nb_attrs > 1)
				oattr = json_object_array_get_idx(oattr_list,
								  idx);
			ret = read_tlv(&tlv[idx], len, oattr);
			if (ret != ERR_CODE(PASSED))
				goto end;
		}

		ret = build_attr_lists(attr, *len, tlv, nb_attrs);
	}

end:
	if (tlv)
		free(tlv);

	return ret;
}
