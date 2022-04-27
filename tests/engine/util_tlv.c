// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "json_types.h"
#include "types.h"
#include "util.h"
#include "util_tlv.h"

#define TLV_NUMERAL_ARRAY_NB_ELEM 2

#define TLV_KEY_POLICY "POLICY"
#define TLV_KEY_USAGE  "USAGE"
#define TLV_KEY_ALGO   "ALGO"

/**
 * struct tlv - TLV structure
 * @type: Type field (string)
 * @type_len: Length of the Type string
 * @length: Length field
 * @val_type: Type of the value (JSON type: string, int, boolean or array)
 * @val_len: Length of the field @value
 * @value: Value field
 */
struct tlv {
	const char *type;
	int type_len;
	unsigned int length;
	enum json_type val_type;
	unsigned int val_len;
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
	json_object *oidx;
	enum json_type type;

	nb_elem = json_object_array_length(obj);
	DBG_PRINT("Get nb array elem %d", nb_elem);

	tlv->type = json_object_get_string(json_object_array_get_idx(obj, 0));
	if (!tlv->type) {
		DBG_PRINT("TLV empty");
		return ret;
	}

	/* Type length without null termination character */
	tlv->type_len = strlen(tlv->type);

	/* Add length of the 'type" and its null termination character */
	*len += tlv->type_len + 1;

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
			tlv->val_len = get_tlv_numeral_byte(tlv->value.num);
			tlv->length = tlv->val_len;
			DBG_PRINT("Type %s, L=%d, V=%ld", tlv->type,
				  tlv->length, tlv->value.num);
			ret = ERR_CODE(PASSED);
			break;

		case json_type_string:
			tlv->value.str = json_object_get_string(ovalue);
			if (tlv->value.str) {
				/*
				 * Length is the string length including
				 * the NULL ending character
				 */
				tlv->val_len = strlen(tlv->value.str) + 1;
				tlv->length = tlv->val_len;
				DBG_PRINT("Type %s, L=%d, V=%s", tlv->type,
					  tlv->length, tlv->value.str);
				ret = ERR_CODE(PASSED);
			}
			break;

		case json_type_array:
			/*
			 * Case for numeral and large numeral TLV type.
			 * The array must be composed of two values:
			 * Index 0: an integer which represent the length field
			 * Index 1: a string that represent the hex value
			 */
			nb_elem = json_object_array_length(ovalue);
			if (nb_elem != TLV_NUMERAL_ARRAY_NB_ELEM) {
				DBG_PRINT("TLV numeral bad 'nb elem'\n");
				break;
			}

			oidx = json_object_array_get_idx(ovalue, 0);
			type = json_object_get_type(oidx);

			if (type != json_type_int) {
				DBG_PRINT("TLV numeral bad 1st elem\n");
				break;
			}

			tlv->val_len = json_object_get_int64(oidx);
			tlv->length = tlv->val_len;

			oidx = json_object_array_get_idx(ovalue, 1);
			type = json_object_get_type(oidx);

			if (type != json_type_string) {
				DBG_PRINT("TLV numeral bad 2nd elem\n");
				break;
			}

			tlv->value.str = json_object_get_string(oidx);

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
	unsigned char *hex_string = NULL;
	unsigned int hex_len = 0;

	if (!len)
		return ERR_CODE(FAILED);

	attr_string = malloc(len);
	if (!attr_string)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	*attr = attr_string;

	/* Build the attributes list with all tlv(s) read */
	for (idx = 0; idx < nb_tlv; idx++) {
		/* Copy the 'type' of TLV */
		memcpy(attr_string, tlv[idx].type, tlv[idx].type_len);
		attr_string += tlv[idx].type_len;
		/* Add the NULL termination */
		*(attr_string++) = '\0';

		/* Set the 'length' of TLV with 2 bytes */
		*(attr_string++) = tlv[idx].length >> CHAR_BIT;
		*(attr_string++) = tlv[idx].length & UCHAR_MAX;

		/* Copy the 'value' of TLV */
		switch (tlv[idx].val_type) {
		case json_type_int:
			for (int nb_bytes = tlv[idx].val_len; nb_bytes;
			     nb_bytes--) {
				*(attr_string++) =
					UCHAR_SHIFT_BYTE(tlv[idx].value.num,
							 nb_bytes - 1);
			}
			continue;

		case json_type_string:
			memcpy(attr_string, tlv[idx].value.str,
			       tlv[idx].val_len);
			break;

		case json_type_boolean:
			break;

		case json_type_array:
			/* Case for numeral and large numeral type */
			ret = util_string_to_hex((char *)tlv[idx].value.str,
						 &hex_string, &hex_len);
			if (ret != ERR_CODE(PASSED))
				goto end;

			if (hex_len != tlv[idx].val_len) {
				DBG_PRINT("TLV length is badly set\n");
				ret = ERR_CODE(FAILED);
				goto end;
			}

			memcpy(attr_string, hex_string, tlv[idx].val_len);
			break;

		default:
			DBG_PRINT("Unsupported TLV of type %d",
				  tlv[idx].val_type);
			ret = ERR_CODE(FAILED);
			goto end;
		}

		attr_string += tlv[idx].val_len;
	}

	ret = ERR_CODE(PASSED);

end:
	if (ret != ERR_CODE(PASSED)) {
		free(*attr);
		*attr = NULL;
	}

	if (hex_string)
		free(hex_string);

	return ret;
}

static int read_key_algo_param(struct tlv *tlv, json_object *oval)
{
	int err = ERR_CODE(FAILED);
	static const char delim[2] = "=";
	char *tmp = NULL;
	char *field = NULL;

	tmp = malloc(json_object_get_string_len(oval) + 1);
	if (!tmp) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	strcpy(tmp, json_object_get_string(oval));

	/* Get the parameter type name */
	field = strtok(tmp, delim);
	if (!field) {
		DBG_PRINT("Key Algo parameter \"%s\" not supported",
			  json_object_get_string(oval));
		err = ERR_CODE(FAILED);
		goto end;
	}

	tlv->type = json_object_get_string(oval);
	tlv->type_len = strlen(field);
	tlv->length = 0;
	tlv->val_len = 0;

	/* Get the parameter value */
	field = strtok(NULL, delim);
	if (!field) {
		/* There is no parameter value assume its a boolean */
		tlv->val_type = json_type_boolean;
		err = ERR_CODE(PASSED);
		goto end;
	}

	if (isdigit((unsigned char)*field)) {
		tlv->val_type = json_type_int;
		tlv->value.num = strtol(field, NULL, 10);
		if (tlv->value.num == LONG_MIN || tlv->value.num == LONG_MAX) {
			DBG_PRINT("Parameter \"%s\" could not be decoded",
				  json_object_get_string(oval));
			err = ERR_CODE(FAILED);
			goto end;
		}
		tlv->val_len = get_tlv_numeral_byte(tlv->value.num);
	} else {
		tlv->val_type = json_type_string;
		tlv->value.str =
			json_object_get_string(oval) + tlv->type_len + 1;
		tlv->val_len = strlen(tlv->value.str) + 1;
	}

	tlv->length = tlv->val_len;

	err = ERR_CODE(PASSED);

end:
	if (tmp)
		free(tmp);

	return err;
}

static int read_key_usage_algo(struct tlv **tlv, unsigned int *policy_len,
			       json_object_iter *usage)
{
	int err = ERR_CODE(PASSED);
	struct json_object *oalgo = NULL;
	struct json_object *oval = NULL;
	struct tlv *ptlv = *tlv;
	struct tlv *ptlv_usage;
	struct tlv *ptlv_algo;
	int nb_elem;
	int nb_algo_params;
	int idx;
	int idx_param;

	ptlv->type = TLV_KEY_USAGE;
	ptlv->type_len = strlen(ptlv->type);
	ptlv->val_type = json_type_string;
	ptlv->value.str = util_string_to_upper(usage->key);
	ptlv->val_len = strlen(ptlv->value.str) + 1;
	ptlv->length = ptlv->val_len;

	/*
	 * Keep reference to TLV USAGE to increase length when
	 * new algorithm is read.
	 */
	ptlv_usage = ptlv;

	ptlv++;

	nb_elem = json_object_array_length(usage->val);
	for (idx = 0; idx < nb_elem; idx++) {
		oalgo = json_object_array_get_idx(usage->val, idx);
		nb_algo_params = json_object_array_length(oalgo);

		/*
		 * First element of the algorithm array is the
		 * algorithm name
		 */
		oval = json_object_array_get_idx(oalgo, 0);

		ptlv->type = TLV_KEY_ALGO;
		ptlv->type_len = strlen(ptlv->type);
		ptlv->val_type = json_type_string;
		ptlv->value.str = json_object_get_string(oval);
		ptlv->val_len = json_object_get_string_len(oval) + 1;
		ptlv->length = ptlv->val_len;

		/*
		 * Keep reference to TLV ALGO to increase length when
		 * new algorithm's parameters are read.
		 */
		ptlv_algo = ptlv;

		ptlv++;

		for (idx_param = 1;
		     idx_param < nb_algo_params && err == ERR_CODE(PASSED);
		     idx_param++, ptlv++) {
			oval = json_object_array_get_idx(oalgo, idx_param);
			err = read_key_algo_param(ptlv, oval);

			ptlv_algo->length +=
				ptlv->type_len + 1 + 2 + ptlv->length;
		}

		/* Increase the key usage length with the new algorithm */
		ptlv_usage->length +=
			ptlv_algo->type_len + 1 + 2 + ptlv_algo->length;
	}

	/* Increase the total policy length with the new key usage */
	*policy_len += ptlv_usage->type_len + 1 + 2 + ptlv_usage->length;

	*tlv = ptlv;

	return err;
}

static int count_tlv_key_usage_algo(int *nb_tlv, json_object_iter *usage)
{
	struct json_object *oalgo = NULL;
	struct json_object *oval = NULL;
	int nb_elem;
	int nb_params;
	int idx;

	nb_elem = json_object_array_length(usage->val);

	/*
	 * key usage is an array of algorithms(s):
	 * Possible format are:
	 * - No algorithm:
	 *     []
	 *
	 * - One or more algorithm, 1st entry is the algorithm, then
	 * parameters' algorithm if any:
	 *    [
	 *        ["algo_1"],
	 *        ["algo_2", "MIN_LENGTH=xx", ...],
	 *        [...]
	 *    ]
	 */
	for (idx = 0; idx < nb_elem; idx++) {
		oalgo = json_object_array_get_idx(usage->val, idx);
		if (json_object_get_type(oalgo) != json_type_array) {
			DBG_PRINT("Usage %s entry #%d must be an array",
				  usage->key, idx);
			return ERR_CODE(FAILED);
		}

		nb_params = json_object_array_length(oalgo);

		if (!nb_params) {
			DBG_PRINT("Usage %s algo name missing", usage->key);
			return ERR_CODE(FAILED);
		}

		*nb_tlv += nb_params;

		oval = json_object_array_get_idx(oalgo, 0);
		if (json_object_get_type(oval) != json_type_string) {
			DBG_PRINT("Usage %s algo name must be a string",
				  usage->key);
			return ERR_CODE(FAILED);
		}

		DBG_PRINT("Usage %s, algo %s is %d parameters", usage->key,
			  json_object_get_string(oval), nb_params - 1);

		for (nb_params--; nb_params; nb_params--) {
			oval = json_object_array_get_idx(oalgo, nb_params);
			if (json_object_get_type(oval) != json_type_string) {
				DBG_PRINT("Usage %s algo #%d must be strings",
					  usage->key, idx);
				return ERR_CODE(FAILED);
			}
		}
	}

	return ERR_CODE(PASSED);
}

static int concat_attr_list(unsigned char **attr, unsigned int *len,
			    unsigned char **add_attr, unsigned int add_attr_len)
{
	unsigned char *new_attr = NULL;

	if (*attr) {
		/*
		 * Input attribute list is not empty, reallocate
		 * a new one and concatenate the new computed attribute
		 * list.
		 */
		new_attr = realloc(*attr, *len + add_attr_len);
		if (!new_attr) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		(void)memcpy(new_attr + *len, *add_attr, add_attr_len);
		*len += add_attr_len;
		*attr = new_attr;

		free(*add_attr);
		*add_attr = NULL;
	} else {
		*attr = *add_attr;
		*len = add_attr_len;
	}

	return ERR_CODE(PASSED);
}

static int concat_policy_attr(unsigned char **attr, unsigned int *len,
			      unsigned char *usages, unsigned int usages_len)
{
	int err;
	char *p;
	unsigned char *policy_attr = NULL;
	unsigned int policy_len = 0;

	policy_len = sizeof(TLV_KEY_POLICY) + 2 + usages_len;
	policy_attr = malloc(policy_len);
	if (!policy_attr) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	p = (char *)policy_attr;
	(void)strcpy(p, TLV_KEY_POLICY);
	p += sizeof(TLV_KEY_POLICY);

	/* Set the 'length' of TLV with 2 bytes */
	*(p++) = usages_len >> CHAR_BIT;
	*(p++) = usages_len & UCHAR_MAX;

	(void)memcpy(p, usages, usages_len);

	err = concat_attr_list(attr, len, &policy_attr, policy_len);

	if (err != ERR_CODE(PASSED) && policy_attr)
		free(policy_attr);

	return err;
}

int util_tlv_read_attrs(unsigned char **attr, unsigned int *len,
			json_object *params)
{
	int ret;
	struct tlv *tlv = NULL;
	json_object *oattr_list;
	json_object *oattr;
	unsigned char *new_attr = NULL;
	unsigned int new_attr_len = 0;
	int nb_attrs = 0;
	int idx;

	if (!params || !attr || !len) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_read_json_type(&oattr_list, ATTR_LIST_OBJ, t_array, params);
	if (ret != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (ret == ERR_CODE(VALUE_NOTFOUND))
			ret = ERR_CODE(PASSED);
		return ret;
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
			oattr = json_object_array_get_idx(oattr_list, idx);
		ret = read_tlv(&tlv[idx], &new_attr_len, oattr);
		if (ret != ERR_CODE(PASSED))
			goto end;
	}

	ret = build_attr_lists(&new_attr, new_attr_len, tlv, nb_attrs);

	/*
	 * Concatenate new attributes with the input attributes if
	 * not empty.
	 */
	if (ret == ERR_CODE(PASSED))
		ret = concat_attr_list(attr, len, &new_attr, new_attr_len);

end:
	if (tlv)
		free(tlv);

	if (ret != ERR_CODE(PASSED) && new_attr)
		free(new_attr);

	return ret;
}

int util_tlv_read_key_policy(unsigned char **attr, unsigned int *len,
			     json_object *params)
{
	int err;
	struct json_object *obj = NULL;
	struct json_object_iter usage;
	struct tlv *tlv = NULL;
	struct tlv *ptlv = NULL;
	int nb_tlv = 0;
	unsigned char *usages_attr = NULL;
	unsigned int usages_len = 0;

	if (!params || !attr || !len) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/*
	 * Key policy is an JSON-C object where each item is a
	 * key usage. Each key usage is an array (empty or not) of
	 * permitted algorithm(s).
	 *
	 * Definition is as below:
	 * "key_policy" : {
	 *     "usage_1" : [],
	 *     "usage_2" : [
	 *         ["algo_1", "MIN_LENGTH=32"],
	 *         ["algo_2"]
	 *     ]
	 * }
	 */
	err = util_read_json_type(&obj, KEY_POLICY_OBJ, t_object, params);
	if (err != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (err == ERR_CODE(VALUE_NOTFOUND))
			err = ERR_CODE(PASSED);
		return err;
	}

	if (!json_object_get_object(obj)) {
		/* Object is empty */
		return ERR_CODE(PASSED);
	}

	/*
	 * First step is to build all usages definition attributes
	 */
	json_object_object_foreachC(obj, usage)
	{
		if (json_object_get_type(usage.val) != json_type_array) {
			DBG_PRINT("Key usage %s must be an array", usage.key);
			return ERR_CODE(FAILED);
		}

		nb_tlv++;

		err = count_tlv_key_usage_algo(&nb_tlv, &usage);
		if (err != ERR_CODE(PASSED))
			return err;
	}

	tlv = calloc(1, nb_tlv * sizeof(*tlv));
	if (!tlv) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	ptlv = tlv;
	json_object_object_foreachC(obj, usage)
	{
		err = read_key_usage_algo(&ptlv, &usages_len, &usage);
		if (err != ERR_CODE(PASSED))
			break;
	}

	if (err == ERR_CODE(PASSED))
		err = build_attr_lists(&usages_attr, usages_len, tlv, nb_tlv);

	free(tlv);

	/*
	 * Second step is to build the final policy attribute starting
	 * with tag Type=POLICY, length is all usages attributes length
	 * computed above and concatenate it with the input attributes.
	 */
	if (err == ERR_CODE(PASSED))
		err = concat_policy_attr(attr, len, usages_attr, usages_len);

	if (usages_attr)
		free(usages_attr);

	return err;
}
