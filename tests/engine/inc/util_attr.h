/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __UTIL_ATTR_H__
#define __UTIL_ATTR_H__

#include <stdint.h>
#include <json_object.h>

#include <smw/attr.h>

#include <psa/crypto_types.h>
#include <psa/crypto_values.h>
#include <psa/storage_common.h>

struct util_attr_info {
	const char *string;

	union {
		smw_attr_algo_t smw_algo;
		smw_attr_storage_id_t smw_storage_id;
		smw_attr_attributes_t smw_attributes;
		smw_attr_usage_t smw_usage;
		psa_algorithm_t psa_algo;
		psa_key_usage_t psa_usage;
		psa_key_lifetime_t psa_lifetime;
	};
};

#define HASH_STR       "HASH="
#define LENGTH_STR     "LENGTH="
#define MIN_LENGTH_STR "MIN_LENGTH="

#define ATTR_USAGE(_string)                                                    \
	{                                                                      \
		.string = #_string, .smw_usage = SMW_ATTR_USAGE_##_string      \
	}

#define ATTR_USAGE_PSA(_string)                                                \
	{                                                                      \
		.string = #_string, .psa_usage = PSA_KEY_USAGE_##_string       \
	}

#define ATTR_HASH(_string)                                                     \
	{                                                                      \
		.string = #_string, .smw_algo = SMW_ATTR_HASH_##_string        \
	}

#define ATTR_HASH_PSA(_string, _algo)                                          \
	{                                                                      \
		.string = #_string,                                            \
		.psa_algo = ((_algo) & (PSA_ALG_HASH_MASK))                    \
	}

#define ATTR_LIFECYCLE(_string)                                                \
	{                                                                      \
		.string = #_string,                                            \
		.smw_attributes = SMW_ATTR_NAME(LIFECYCLE, _string)            \
	}

#define ATTR_RW_FLAGS(_string)                                                 \
	{                                                                      \
		.string = #_string,                                            \
		.smw_attributes = SMW_ATTR_NAME(RW_FLAGS, _string)             \
	}

#define ATTR_PERSISTENCE(_string)                                              \
	{                                                                      \
		.string = #_string,                                            \
		.smw_attributes = SMW_ATTR_NAME(PERSISTENCE, _string)          \
	}

#define ATTR_LIFETIME_PSA(_string)                                             \
	{                                                                      \
		.string = #_string, .psa_lifetime = PSA_KEY_LIFETIME_##_string \
	}

#define ATTR_ALGO(_string, _class, _algo, _mode, _hash)                        \
	{                                                                      \
		.string = #_string,                                            \
		.smw_algo = (((SMW_ATTR_HASH_##_hash & SMW_ATTR_HASH_MASK)     \
			      << SMW_ATTR_HASH_OFFSET) |                       \
			     ((SMW_ATTR_MODE_##_mode & SMW_ATTR_MODE_MASK)     \
			      << SMW_ATTR_MODE_OFFSET) |                       \
			     ((SMW_ATTR_ALGO_##_algo & SMW_ATTR_ALGO_MASK)     \
			      << SMW_ATTR_ALGO_OFFSET) |                       \
			     ((SMW_ATTR_CLASS_##_class & SMW_ATTR_CLASS_MASK)  \
			      << SMW_ATTR_CLASS_OFFSET))                       \
	}

#define ATTR_ALGO_PSA(_string, _algo)                                          \
	{                                                                      \
		.string = #_string, .psa_algo = _algo                          \
	}

#define ATTR_ALGO_CURVE(_string, _class, _algo, _curve, _hash)                 \
	{                                                                      \
		.string = #_string,                                            \
		.smw_algo = (((SMW_ATTR_HASH_##_hash & SMW_ATTR_HASH_MASK)     \
			      << SMW_ATTR_HASH_OFFSET) |                       \
			     ((SMW_ATTR_CURVE_##_curve & SMW_ATTR_CURVE_MASK)  \
			      << SMW_ATTR_CURVE_OFFSET) |                      \
			     ((SMW_ATTR_ALGO_##_algo & SMW_ATTR_ALGO_MASK)     \
			      << SMW_ATTR_ALGO_OFFSET) |                       \
			     ((SMW_ATTR_CLASS_##_class & SMW_ATTR_CLASS_MASK)  \
			      << SMW_ATTR_CLASS_OFFSET))                       \
	}

#define ATTR_ARRAY_FIND_MATCH(_array, _string)                                 \
	({                                                                     \
		typeof(_array[0]) *_elm = (_array);                            \
		typeof(_string) _n = (_string);                                \
		struct util_attr_info _ret = { 0 };                            \
		while (_elm->string && _n) {                                   \
			if (!strcmp(_elm->string, _n)) {                       \
				_ret = *_elm;                                  \
				break;                                         \
			}                                                      \
			_elm++;                                                \
		}                                                              \
		_ret;                                                          \
	})

typedef void attribute_callback(void *user_data, const char *attributes[],
				size_t n_attributes);

/**
 * util_attr_read_attributes() - Read attributes
 * @params: json-c parameters.
 * @key: Key value to read.
 * @callback: Function that stores the attributes.
 * @user_data: Address where the attributes are written.
 *
 * Return:
 * PASSED       - Success.
 * -INTERNAL    - Internal error.
 */
int util_attr_read_attributes(struct json_object *params, const char *key,
			      attribute_callback callback, void *user_data);

#endif /* __UTIL_ATTR_H__ */
