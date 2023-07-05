// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "json_types.h"
#include "types.h"
#include "util.h"
#include "util_key.h"
#include "util_tlv.h"

#define TLV_NUMERAL_ARRAY_NB_ELEM 2

#define TLV_KEY_POLICY "POLICY"
#define TLV_KEY_USAGE  "USAGE"
#define TLV_KEY_ALGO   "ALGO"
#define TLV_LIFECYCLE  "LIFECYCLE"

/* TLV defines */
#define TLV_LENGTH_FIELD_SIZE 2 /* TLV length encoded with 2 bytes */

#define TLV_ELEMENT_LENGTH(_type, _value_size, _res)                           \
	({                                                                     \
		int _ret = 1;                                                  \
		size_t _l_type = strlen(_type) + 1;                            \
		__typeof__(_res) _l = 0;                                       \
		/* Add length of Type + length of Length */                    \
		if (!ADD_OVERFLOW(_l_type, TLV_LENGTH_FIELD_SIZE, &_l)) {      \
			/* Append length of Value */                           \
			if (!ADD_OVERFLOW(_l, _value_size, &(_res)))           \
				_ret = 0;                                      \
		}                                                              \
		_ret;                                                          \
	})

/**
 * struct tlv - TLV structure
 * @type: Type field (string)
 * @type_len: Length of the Type string
 * @length: Length field
 * @val_type: Type of the value (JSON type: string, int, boolean or array)
 * @val_len: Length of the field @value
 * @value_alloc: 1 if the value is allocated buffer
 * @value: Value field
 */
struct tlv {
	const char *type;
	size_t type_len;
	size_t length;
	enum json_type val_type;
	size_t val_len;
	int value_alloc;
	union {
		long num;
		const char *str;
		void *ptr;
	} value;
};

/**
 * struct tlv_list - List of TLV entries (variable-length list)
 * @verified: TLV entry verified
 * @tlv: TLV entry
 * @tlv_list: Sub list of TLVs entries
 * @next: Next TLV entry
 */
struct tlv_list {
	bool verified;
	struct tlv *tlv;
	struct tlv_list *tlv_list;
	struct tlv_list *next;
};

static void free_tlvs(struct tlv **tlv, size_t nb_tlv)
{
	size_t idx = 0;
	struct tlv *ptlv = NULL;

	if (tlv && *tlv) {
		for (ptlv = *tlv; idx < nb_tlv; idx++, ptlv++) {
			if (ptlv->value_alloc)
				free(ptlv->value.ptr);
		}

		free(*tlv);
		*tlv = NULL;
	}
}

static int concat_buffers(void **buf, size_t *len, void *add_buf,
			  size_t add_len)
{
	unsigned int new_len = 0;
	void *new_buf = NULL;

	if (*buf) {
		/*
		 * Input buffer is not empty, reallocate a new one
		 * and concatenate the new buffer.
		 */
		if (ADD_OVERFLOW(*len, add_len, &new_len))
			return ERR_CODE(FAILED);

		new_buf = realloc(*buf, new_len);
		if (!new_buf) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		(void)memcpy(new_buf + *len, add_buf, add_len);

		*buf = new_buf;
		*len = new_len;
	} else {
		*buf = add_buf;
		*len = add_len;
	}

	return ERR_CODE(PASSED);
}

static unsigned int get_tlv_numeral_byte(long value)
{
	long val = value;
	unsigned int nb_bytes = 0;

	do {
		if (INC_OVERFLOW(nb_bytes, 1))
			return 0;

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

static int read_tlv(struct tlv *tlv, size_t *len, struct json_object *obj)
{
	int ret = ERR_CODE(FAILED);
	size_t idx_val = 0;
	size_t nb_val = 0;
	size_t nb_elem = 0;
	struct json_object *ovalue = NULL;
	struct json_object *oidx = NULL;
	enum json_type type = json_type_null;
	size_t tlv_elem_length = 0;
	int64_t int64_val = 0;
	char *tmp_str = NULL;
	int json_str_len = 0;
	size_t tmp_str_len = 0;

	nb_val = json_object_array_length(obj);
	DBG_PRINT("Get nb array elem %d", nb_val);

	tlv->type = json_object_get_string(json_object_array_get_idx(obj, 0));
	if (!tlv->type) {
		DBG_PRINT("TLV empty");
		return ret;
	}

	/* Type length without null termination character */
	tlv->type_len = strlen(tlv->type);

	/* Initialize tlv->length to json null type */
	tlv->length = 0;

	/* Initialize tlv->type to null */
	tlv->val_type = json_type_null;

	/* Calculate the tlv element length with a value of 0 */
	TLV_ELEMENT_LENGTH(tlv->type, tlv->length, tlv_elem_length);

	if (INC_OVERFLOW(*len, tlv_elem_length)) {
		DBG_PRINT("TLV length overflow");
		return ERR_CODE(FAILED);
	}

	if (nb_val == 1) {
		DBG_PRINT("Type %s, L=%d", tlv->type, tlv->length);
		tlv->val_type = json_type_boolean;
		ret = ERR_CODE(PASSED);
	}

	for (idx_val = 1; idx_val < nb_val; idx_val++) {
		ovalue = json_object_array_get_idx(obj, idx_val);

		if (tlv->val_type == json_type_null) {
			tlv->val_type = json_object_get_type(ovalue);
		} else if (tlv->val_type != json_object_get_type(ovalue)) {
			ret = ERR_CODE(FAILED);
			goto error;
		}

		switch (tlv->val_type) {
		case json_type_int:
			int64_val = json_object_get_int64(ovalue);

			/* Number of bytes used to code the value */
			tlv->value.num = int64_val & LONG_MAX;
			tlv->val_len = get_tlv_numeral_byte(tlv->value.num);
			tlv->length = tlv->val_len;
			DBG_PRINT("Type %s, L=%d, V=%ld", tlv->type,
				  tlv->length, tlv->value.num);
			ret = ERR_CODE(PASSED);
			goto end;

		case json_type_string:
			/*
			 * Length is the string length including
			 * the NULL ending character
			 */
			json_str_len = json_object_get_string_len(ovalue);
			if (json_str_len &&
			    !ADD_OVERFLOW(json_str_len, 1, &tmp_str_len)) {
				tmp_str = malloc(tmp_str_len);
				if (!tmp_str) {
					DBG_PRINT_ALLOC_FAILURE();
					return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				}

				(void)memcpy(tmp_str,
					     json_object_get_string(ovalue),
					     tmp_str_len);
				ret = concat_buffers((void **)&tlv->value.str,
						     &tlv->val_len,
						     (void *)tmp_str,
						     tmp_str_len);

				if (tlv->value.str != tmp_str)
					free(tmp_str);

				if (ret != ERR_CODE(PASSED))
					return ret;

				tlv->value_alloc = 1;

				if (INC_OVERFLOW(tlv->length, tmp_str_len))
					return ERR_CODE(INTERNAL);

				DBG_PRINT("Type %s, L=%d, V=%s", tlv->type,
					  tlv->length, tlv->value.str);
				ret = ERR_CODE(PASSED);
			} else {
				ret = ERR_CODE(FAILED);
				goto error;
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

			int64_val = json_object_get_int64(oidx);
			if (SET_OVERFLOW(int64_val, tlv->val_len)) {
				DBG_PRINT("TLV numeral length invalid\n");
				break;
			}

			tlv->length = tlv->val_len;

			oidx = json_object_array_get_idx(ovalue, 1);
			type = json_object_get_type(oidx);

			if (type != json_type_string) {
				DBG_PRINT("TLV numeral bad 2nd elem\n");
				break;
			}

			tlv->value.str = json_object_get_string(oidx);

			ret = ERR_CODE(PASSED);
			goto end;

		default:
			DBG_PRINT("TLV Value of type %d not supported",
				  tlv->val_type);
			ret = ERR_CODE(FAILED);
			goto error;
		}
	}

end:
	/*
	 * Add length of the 'value' defined by tlv->length
	 * If no value, tlv->length is 0.
	 */
	if (INC_OVERFLOW(*len, tlv->length))
		ret = ERR_CODE(FAILED);

error:
	return ret;
}

static int build_attr_lists(unsigned char **attr, size_t len, struct tlv *tlv,
			    int nb_tlv)
{
	int ret = ERR_CODE(FAILED);
	int idx = 0;
	unsigned char *attr_string = NULL;
	unsigned char *hex_string = NULL;
	unsigned int hex_len = 0;
	size_t nb_bytes = 0;

	if (!len)
		return ret;

	attr_string = malloc(len);
	if (!attr_string)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	*attr = attr_string;

	/* Build the attributes list with all tlv(s) read */
	for (; idx < nb_tlv; idx++) {
		/* Copy the 'type' of TLV */
		memcpy(attr_string, tlv[idx].type, tlv[idx].type_len);
		attr_string += tlv[idx].type_len;
		/* Add the NULL termination */
		*(attr_string++) = '\0';

		/* Set the 'length' of TLV with 2 bytes */
		*(attr_string++) = GET_BYTE(tlv[idx].length, 1);
		*(attr_string++) = GET_BYTE(tlv[idx].length, 0);

		/* Copy the 'value' of TLV */
		switch (tlv[idx].val_type) {
		case json_type_int:
			for (nb_bytes = tlv[idx].val_len; nb_bytes; nb_bytes--)
				*(attr_string++) = GET_BYTE(tlv[idx].value.num,
							    nb_bytes - 1);
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

			free(hex_string);
			hex_string = NULL;

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

static int read_key_algo_param(struct tlv *tlv, struct json_object *oval)
{
	int err = ERR_CODE(FAILED);
	static const char delim[2] = "=";
	char *tmp = NULL;
	char *field = NULL;
	int json_str_len = 0;

	json_str_len = json_object_get_string_len(oval);
	if (!json_str_len || INC_OVERFLOW(json_str_len, 1))
		return err;

	tmp = malloc(json_str_len);
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
		tlv->val_len = strlen(tlv->value.str);
		if (INC_OVERFLOW(tlv->val_len, 1)) {
			err = ERR_CODE(FAILED);
			goto end;
		}
	}

	tlv->length = tlv->val_len;

	err = ERR_CODE(PASSED);

end:
	if (tmp)
		free(tmp);

	return err;
}

static int read_key_usage_algo(struct tlv **tlv, size_t *policy_len,
			       struct json_object_iter *usage)
{
	int err = ERR_CODE(PASSED);
	struct json_object *oalgo = NULL;
	struct json_object *oval = NULL;
	struct tlv *ptlv = *tlv;
	struct tlv *ptlv_usage = NULL;
	struct tlv *ptlv_algo = NULL;
	size_t tlv_elem_length = 0;
	size_t nb_elem = 0;
	size_t nb_algo_params = 0;
	size_t idx = 0;
	size_t idx_param = 0;
	size_t val_len = 0;
	int json_str_len = 0;

	ptlv->type = TLV_KEY_USAGE;
	ptlv->type_len = strlen(ptlv->type);
	ptlv->val_type = json_type_string;
	ptlv->value.str = util_string_to_upper(usage->key);

	val_len = strlen(ptlv->value.str);
	if (ADD_OVERFLOW(val_len, 1, &ptlv->val_len))
		return ERR_CODE(FAILED);

	ptlv->length = ptlv->val_len;

	/*
	 * Keep reference to TLV USAGE to increase length when
	 * new algorithm is read.
	 */
	ptlv_usage = ptlv;

	ptlv++;

	nb_elem = json_object_array_length(usage->val);
	for (; idx < nb_elem; idx++) {
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

		json_str_len = json_object_get_string_len(oval);
		if (!json_str_len ||
		    ADD_OVERFLOW(json_str_len, 1, &ptlv->val_len))
			return ERR_CODE(FAILED);

		ptlv->length = ptlv->val_len;

		/*
		 * Keep reference to TLV ALGO to increase length when
		 * new algorithm's parameters are read.
		 */
		ptlv_algo = ptlv;

		ptlv++;

		for (idx_param = 1; idx_param < nb_algo_params;
		     idx_param++, ptlv++) {
			oval = json_object_array_get_idx(oalgo, idx_param);
			err = read_key_algo_param(ptlv, oval);

			if (err != ERR_CODE(PASSED))
				break;

			/*
			 * Calculate the additional algorithm parameter
			 * defined.
			 * Don't use ptlv->type in the TLV_ELEMENT_LENGTH()
			 * macro here as the ptlv->type is the full parameter
			 * string (e.g. HASH=SHA256)
			 */
			TLV_ELEMENT_LENGTH("\0", ptlv->length, tlv_elem_length);
			if (INC_OVERFLOW(tlv_elem_length, ptlv->type_len) ||
			    INC_OVERFLOW(ptlv_algo->length, tlv_elem_length))
				err = ERR_CODE(FAILED);
		}

		if (err == ERR_CODE(FAILED))
			break;

		/* Increase the key usage length with the new algorithm */
		TLV_ELEMENT_LENGTH(ptlv_algo->type, ptlv_algo->length,
				   tlv_elem_length);
		if (INC_OVERFLOW(ptlv_usage->length, tlv_elem_length))
			err = ERR_CODE(FAILED);
	}

	if (err == ERR_CODE(PASSED)) {
		/* Increase the total policy length with the new key usage */
		TLV_ELEMENT_LENGTH(ptlv_usage->type, ptlv_usage->length,
				   tlv_elem_length);
		if (INC_OVERFLOW(*policy_len, tlv_elem_length))
			err = ERR_CODE(FAILED);
	}

	*tlv = ptlv;

	return err;
}

static int count_tlv_key_usage_algo(size_t *nb_tlv,
				    struct json_object_iter *usage)
{
	struct json_object *oalgo = NULL;
	struct json_object *oval = NULL;
	size_t nb_elem = 0;
	size_t nb_params = 0;
	size_t idx = 0;

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
	for (; idx < nb_elem; idx++) {
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

		if (INC_OVERFLOW(*nb_tlv, nb_params)) {
			DBG_PRINT("Too much parameters");
			return ERR_CODE(FAILED);
		}

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

static int concat_policy_attr(unsigned char **attr, size_t *len,
			      unsigned char *usages, size_t usages_len)
{
	int err = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	unsigned char *p = NULL;
	unsigned char *policy_attr = NULL;
	size_t policy_len = 0;

	TLV_ELEMENT_LENGTH(TLV_KEY_POLICY, usages_len, policy_len);
	if (policy_len < sizeof(TLV_KEY_POLICY))
		return err;

	policy_attr = malloc(policy_len);
	if (!policy_attr) {
		DBG_PRINT_ALLOC_FAILURE();
		return err;
	}

	p = policy_attr;
	(void)strcpy((char *)p, TLV_KEY_POLICY);
	p += sizeof(TLV_KEY_POLICY);

	/* Set the 'length' of TLV with 2 bytes */
	*(p++) = GET_BYTE(usages_len, 1);
	*(p++) = GET_BYTE(usages_len, 0);

	(void)memcpy(p, usages, usages_len);

	err = concat_buffers((void **)attr, len, (void *)policy_attr,
			     policy_len);

	if (policy_attr && *attr != policy_attr)
		free(policy_attr);

	return err;
}

static void free_tlv_list(struct tlv_list **tlv_list)
{
	struct tlv_list *entry = NULL;
	struct tlv_list *next = NULL;

	if (tlv_list) {
		entry = *tlv_list;
		while (entry) {
			free_tlvs(&entry->tlv, 1);

			if (entry->tlv_list)
				free_tlv_list(&entry->tlv_list);

			next = entry->next;
			free(entry);

			entry = next;
		}

		*tlv_list = NULL;
	}
}

static int tlv_convert_numeral(long *numeral, size_t length,
			       const unsigned char *value)
{
	int err = ERR_CODE(FAILED);
	size_t i = 0;

	*numeral = 0;

	if (length <= sizeof(*numeral)) {
		for (; i < length; i++)
			*numeral |= (long)value[i] << ((length - 1 - i) * 8);

		err = ERR_CODE(PASSED);
	} else {
		DBG_PRINT("TLV numeral decoding error\n");
	}

	return err;
}

static unsigned int tlv_length(const unsigned char **str)
{
	int j = 1;
	unsigned int value_length = 0;
	const unsigned char *p = *str;

	value_length = *p++;
	for (; j < TLV_LENGTH_FIELD_SIZE; j++) {
		value_length <<= 8;
		value_length |= *p++;
	}

	*str = p;

	return value_length;
}

static int parse_tlv_list(struct tlv_list **tlv_list, const unsigned char **str,
			  const unsigned char *end)
{
	int err = ERR_CODE(INTERNAL);

	struct tlv *entry = NULL;
	struct tlv_list **list_elem = NULL;
	const unsigned char *p = *str;
	const unsigned char *p_end = NULL;
	size_t value_length = 0;
	size_t tmp_len = 0;

	if (!tlv_list)
		return err;

	*tlv_list = calloc(1, sizeof(**tlv_list));
	if (!*tlv_list) {
		DBG_PRINT_ALLOC_FAILURE();
		err = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		DBG_PRINT_ALLOC_FAILURE();
		err = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	/*
	 * TLV list entry is defined:
	 *   TYPE | LENGTH | VALUE
	 * TYPE is a string
	 * LENGTH is the nummber of bytes of VALUE
	 * VALUE is either:
	 *  - one string
	 *  - one numeral
	 *  - one string + other TLV(s)
	 *
	 * The input @str may not be a null-terminated string in case
	 * last type is a numeral value.
	 * note: numeral is either 1, 2, 4, 8 bytes (limit is 64 bits value)
	 *
	 * If VALUE is:
	 *  - one string,
	 *       LENGTH = strlen(VALUE) + 1
	 *  - one numeral,
	 *       LENGTH = nb bytes defining the numeral
	 *  - one string + other TLV(s),
	 *       LENGTH = strlen(TYPE) + 1 + nb bytes defining other TLV(s)
	 */
	(*tlv_list)->tlv = entry;
	entry->type = (const char *)p;
	entry->type_len = strlen(entry->type) + 1;

	p += entry->type_len;
	if (p > end || !entry->type_len) {
		err = ERR_CODE(INTERNAL);
		goto exit;
	}

	value_length = tlv_length(&p);

	DBG_PRINT("Decoding TYPE=%s LENGTH=%d", entry->type, value_length);

	if (!((uintptr_t)end - (uintptr_t)p >= value_length)) {
		DBG_PRINT("TLV string is too small p=%p end=%p", p, end);
		err = ERR_CODE(FAILED);
		goto exit;
	}

	/* Determine how VALUE is encoded */
	tmp_len = strlen((const char *)p);

	if (tmp_len >= value_length) {
		/* It's one numeral */
		err = tlv_convert_numeral(&entry->value.num, value_length, p);
		if (err != ERR_CODE(PASSED))
			goto exit;

		entry->val_len = value_length;
		entry->val_type = json_type_int;
		DBG_PRINT("VALUE is numeral %s=%lu", entry->type,
			  entry->value.num);

		p += entry->val_len;

		err = ERR_CODE(PASSED);

	} else if (tmp_len + 1 == value_length) {
		/* It's one string */
		entry->value.str = (const char *)p;
		entry->val_len = value_length;
		entry->val_type = json_type_string;
		DBG_PRINT("VALUE is string %s=%s", entry->type,
			  entry->value.str);

		p += entry->val_len;

		err = ERR_CODE(PASSED);
	} else {
		entry->value.str = (const char *)p;
		entry->val_len = tmp_len + 1;
		entry->val_type = json_type_string;
		DBG_PRINT("VALUE is string + other TLVs %s=%s", entry->type,
			  entry->value.str);

		/* It's other TLV(s) */
		p_end = p + value_length;
		p += entry->val_len;
		list_elem = &(*tlv_list)->tlv_list;

		do {
			err = parse_tlv_list(list_elem, &p, p_end);
			if (err == ERR_CODE(PASSED))
				list_elem = &(*list_elem)->next;
		} while (err == ERR_CODE(PASSED) && p < p_end);
	}

exit:
	if (err == ERR_CODE(PASSED))
		*str = p;

	return err;
}

static bool check_tlvs(struct tlv *ref_tlv, struct tlv *tlv)
{
	bool ret = false;

	if (!ref_tlv || !tlv)
		goto exit;

	/* Compare the Type of the TLV */
	if (ref_tlv->type_len != tlv->type_len)
		goto exit;

	if (strcmp(ref_tlv->type, tlv->type))
		goto exit;

	/* Compare the Value */
	if (ref_tlv->val_type == tlv->val_type) {
		switch (ref_tlv->val_type) {
		case json_type_int:
			if (ref_tlv->value.num == tlv->value.num) {
				DBG_PRINT("Found %s=%lu", tlv->type,
					  tlv->value.num);
				ret = true;
			}
			break;

		case json_type_string:
			if (ref_tlv->val_len == tlv->val_len &&
			    !strcmp(ref_tlv->value.str, tlv->value.str)) {
				DBG_PRINT("Found %s=%s", tlv->type,
					  tlv->value.str);
				ret = true;
			}
			break;

		default:
			break;
		}
	}

exit:
	return ret;
}

static void check_tlv_lists(struct tlv_list *ref_policy,
			    struct tlv_list *policy)
{
	struct tlv_list *ref_entry = ref_policy;
	struct tlv_list *entry = NULL;

	for (; ref_entry; ref_entry = ref_entry->next) {
		for (entry = policy; entry && !ref_entry->verified;
		     entry = entry->next) {
			if (entry->verified)
				continue;

			ref_entry->verified =
				check_tlvs(ref_entry->tlv, entry->tlv);

			if (!ref_entry->verified)
				continue;

			entry->verified = true;

			if (ref_entry->tlv_list && entry->tlv_list) {
				check_tlv_lists(ref_entry->tlv_list,
						entry->tlv_list);
			}
		}
	}
}

static int report_policy_comparison(struct tlv_list *list)
{
	int error = 0;
	struct tlv_list *entry = list;

	for (; entry; entry = entry->next) {
		if (!entry->verified && entry->tlv) {
			if (INC_OVERFLOW(error, 1)) {
				error = -1;
				break;
			}

			switch (entry->tlv->val_type) {
			case json_type_int:
				DBG_PRINT("Policy %s=%s not verified",
					  entry->tlv->type,
					  entry->tlv->value.str);
				break;

			case json_type_string:
				DBG_PRINT("Policy %s=%s not verified",
					  entry->tlv->type,
					  entry->tlv->value.str);
				break;

			default:
				DBG_PRINT("Policy %s unknown type",
					  entry->tlv->type);
				break;
			}
		}

		if (entry->tlv_list)
			error += report_policy_comparison(entry->tlv_list);
	}

	return error;
}

static int compare_policy_lists(struct tlv_list *ref_policy,
				struct tlv_list *policy)
{
	int res = ERR_CODE(FAILED);
	int ref_error = 0;
	int error = 0;

	check_tlv_lists(ref_policy, policy);

	DBG_PRINT("Report missing value(s) in policy reference");
	ref_error = report_policy_comparison(ref_policy);
	if (ref_error < 0) {
		DBG_PRINT("Too much missing values in policy reference");
		return res;
	}

	DBG_PRINT("Missing %d value(s) in policy reference", ref_error);

	DBG_PRINT("Report missing value(s) in policy retrieved");
	error = report_policy_comparison(policy);
	if (error < 0) {
		DBG_PRINT("Too much missing values in policy reference");
		return res;
	}

	DBG_PRINT("Missing %d value(s) in policy retrieved", error);

	if (!error && !ref_error)
		res = ERR_CODE(PASSED);

	return res;
}

int util_tlv_read_attrs(unsigned char **attr, unsigned int *len,
			struct json_object *params)
{
	int ret = ERR_CODE(BAD_ARGS);
	struct tlv *tlv = NULL;
	struct json_object *oattr_list = NULL;
	struct json_object *oattr = NULL;
	unsigned char *new_attr = NULL;
	size_t new_attr_len = 0;
	size_t nb_attrs = 0;
	size_t idx = 0;
	size_t tlvs_size = 0;
	size_t output_len = 0;

	if (!params || !attr || !len) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	if (SET_OVERFLOW(*len, output_len)) {
		DBG_PRINT_BAD_ARGS();
		return ret;
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

	if (MUL_OVERFLOW(nb_attrs, sizeof(*tlv), &tlvs_size))
		return ERR_CODE(BAD_ARGS);

	tlv = calloc(1, tlvs_size);
	if (!tlv)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	for (; idx < nb_attrs; idx++) {
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
	if (ret == ERR_CODE(PASSED)) {
		ret = concat_buffers((void **)attr, &output_len,
				     (void *)new_attr, new_attr_len);
		if (ret == ERR_CODE(PASSED) && SET_OVERFLOW(output_len, *len))
			ret = ERR_CODE(FAILED);
	}

end:
	free_tlvs(&tlv, nb_attrs);

	if (new_attr && *attr != new_attr)
		free(new_attr);

	return ret;
}

int util_tlv_read_key_policy(unsigned char **attr, unsigned int *len,
			     struct json_object *okey)
{
	int err = ERR_CODE(BAD_ARGS);
	struct json_object *obj = NULL;
	struct json_object_iter usage = { 0 };
	struct tlv *tlv = NULL;
	struct tlv *ptlv = NULL;
	size_t nb_tlv = 0;
	size_t tlvs_size = 0;
	unsigned char *usages_attr = NULL;
	size_t usages_len = 0;
	size_t output_len = 0;

	if (!okey || !attr || !len) {
		DBG_PRINT_BAD_ARGS();
		return err;
	}

	if (SET_OVERFLOW(*len, output_len)) {
		DBG_PRINT_BAD_ARGS();
		return err;
	}

	/*
	 * Key policy is a JSON-C object where each item is a
	 * key usage. Each key usage is an array (empty or not) of
	 * permitted algorithm(s).
	 *
	 * Definition is as below:
	 * "policy" : {
	 *     "usage_1" : [],
	 *     "usage_2" : [
	 *         ["algo_1", "MIN_LENGTH=32"],
	 *         ["algo_2"]
	 *     ]
	 * }
	 */
	err = util_read_json_type(&obj, POLICY_OBJ, t_object, okey);
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

		if (INC_OVERFLOW(nb_tlv, 1))
			return ERR_CODE(INTERNAL);

		err = count_tlv_key_usage_algo(&nb_tlv, &usage);
		if (err != ERR_CODE(PASSED))
			return err;
	}

	if (!nb_tlv || MUL_OVERFLOW(nb_tlv, sizeof(*tlv), &tlvs_size))
		return ERR_CODE(INTERNAL);

	tlv = calloc(1, tlvs_size);
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

	free_tlvs(&tlv, nb_tlv);

	/*
	 * Second step is to build the final policy attribute starting
	 * with tag Type=POLICY, length is all usages attributes length
	 * computed above and concatenate it with the input attributes.
	 */
	if (err == ERR_CODE(PASSED)) {
		err = concat_policy_attr(attr, &output_len, usages_attr,
					 usages_len);
		if (err == ERR_CODE(PASSED) && SET_OVERFLOW(output_len, *len))
			err = ERR_CODE(FAILED);
	}

	if (usages_attr)
		free(usages_attr);

	return err;
}

int util_tlv_check_key_policy(struct subtest_data *subtest,
			      const unsigned char *policy,
			      unsigned int policy_len)
{
	int res = ERR_CODE(BAD_ARGS);

	int error = 0;
	struct json_object *okey_params = NULL;
	unsigned char *ref_policy = NULL;
	unsigned int ref_policy_len = 0;
	const unsigned char *p = NULL;
	const unsigned char *p_end = NULL;
	unsigned int p_len = 0;
	struct tlv_list *tlv_list = NULL;
	struct tlv_list *ref_tlv_list = NULL;
	struct tlv_list **list_elem = NULL;

	if (!policy || !policy_len) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_key_get_key_params(subtest, KEY_NAME_OBJ, &okey_params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_tlv_read_key_policy(&ref_policy, &ref_policy_len,
				       okey_params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (policy_len > ref_policy_len) {
		DBG_PRINT("Policy length is %u expected maximum %u bytes",
			  policy_len, ref_policy_len);
		error = 1;
	}

	/* Check first if policy is starting with POLICY string */
	if (strncmp((const char *)policy, TLV_KEY_POLICY,
		    MIN(policy_len, strlen(TLV_KEY_POLICY)))) {
		DBG_PRINT("Policy string is not starting with %s",
			  TLV_KEY_POLICY);
		error = 1;
		goto exit;
	}

	DBG_DHEX("POLICY Reference", (void *)ref_policy, ref_policy_len);
	DBG_DHEX("POLICY Retrieved", (void *)policy, policy_len);

	/*
	 * Build the TLV list of the key policy given
	 */
	p = policy + strlen(TLV_KEY_POLICY) + 1;
	p_end = policy + policy_len;

	p_len = tlv_length(&p);
	if (!p_len) {
		DBG_PRINT("Policy variable list is empty");
		error = 1;
		goto exit;
	}

	if (p_len != (uintptr_t)p_end - (uintptr_t)p) {
		DBG_PRINT("Policy buffer and list lengths not equal");
		error = 1;
		goto exit;
	}

	list_elem = &tlv_list;
	do {
		res = parse_tlv_list(list_elem, &p, p_end);
		list_elem = &(*list_elem)->next;
	} while (res == ERR_CODE(PASSED) && p < p_end);

	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Build the TLV list of the key policy reference
	 */
	p = ref_policy + strlen(TLV_KEY_POLICY) + 1;

	p_len = tlv_length(&p);
	if (!p_len) {
		DBG_PRINT("Reference Policy variable list is empty");
		error = 1;
		goto exit;
	}

	p_end = p + p_len;
	list_elem = &ref_tlv_list;
	do {
		res = parse_tlv_list(list_elem, &p, p_end);
		if (res == ERR_CODE(PASSED))
			list_elem = &(*list_elem)->next;
	} while (res == ERR_CODE(PASSED) && p < p_end);

	if (res == ERR_CODE(PASSED))
		res = compare_policy_lists(ref_tlv_list, tlv_list);

exit:
	if (error)
		res = ERR_CODE(FAILED);

	if (ref_policy)
		free(ref_policy);

	free_tlv_list(&tlv_list);
	free_tlv_list(&ref_tlv_list);

	return res;
}

int util_tlv_check_lifecycle(const unsigned char *lifecyle,
			     unsigned int lifecycle_len)
{
	const unsigned char *p = lifecyle;
	const unsigned char *p_end = NULL;
	unsigned int p_len = 0;

	if (!lifecyle && !lifecycle_len)
		return ERR_CODE(PASSED);

	if (!lifecyle && lifecycle_len) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (lifecyle && !lifecycle_len) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Check first if lifecycle is starting with LIFECYCLE string */
	if (strncmp((const char *)lifecyle, TLV_LIFECYCLE,
		    MIN(lifecycle_len, strlen(TLV_LIFECYCLE)))) {
		DBG_PRINT("Lifecycle string is not starting with %s",
			  TLV_LIFECYCLE);
		return ERR_CODE(FAILED);
	}

	DBG_DHEX("LIFECYCLE Retrieved", (void *)lifecyle, lifecycle_len);

	p_end = p + lifecycle_len;
	p += strlen(TLV_LIFECYCLE) + 1;

	p_len = tlv_length(&p);
	if (!p_len) {
		DBG_PRINT("Lifecycle variable list is empty");
		return ERR_CODE(FAILED);
	}

	if (p_len != (uintptr_t)p_end - (uintptr_t)p) {
		DBG_PRINT("Lifecycle buffer and list length not equal");
		return ERR_CODE(FAILED);
	}

	DBG_PRINT("Lifecycle(s):");
	while (p < p_end) {
		DBG_PRINT("\t - %s", p);
		p += strlen((const char *)p) + 1;
	}

	return ERR_CODE(PASSED);
}
