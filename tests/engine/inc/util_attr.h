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
	const char *name;

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

#define ATTR_USAGE(_name)                                                      \
	{                                                                      \
		.name = #_name, .smw_usage = SMW_ATTR_USAGE_##_name            \
	}

#define ATTR_USAGE_PSA(_name)                                                  \
	{                                                                      \
		.name = #_name, .psa_usage = PSA_KEY_USAGE_##_name             \
	}

#define ATTR_HASH(_name)                                                       \
	{                                                                      \
		.name = #_name, .smw_algo = SMW_ATTR_HASH_##_name              \
	}

#define ATTR_HASH_PSA(_name, _algo)                                            \
	{                                                                      \
		.name = _name, .psa_algo = ((_algo) & (PSA_ALG_HASH_MASK))     \
	}

#define ATTR_LIFECYCLE(_name)                                                  \
	{                                                                      \
		.name = #_name,                                                \
		.smw_attributes = SMW_ATTR_NAME(LIFECYCLE, _name)              \
	}

#define ATTR_RW_FLAGS(_name)                                                   \
	{                                                                      \
		.name = #_name,                                                \
		.smw_attributes = SMW_ATTR_NAME(RW_FLAGS, _name)               \
	}

#define ATTR_PERSISTENCE(_name)                                                \
	{                                                                      \
		.name = #_name,                                                \
		.smw_attributes = SMW_ATTR_NAME(PERSISTENCE, _name)            \
	}

#define ATTR_LIFETIME_PSA(_name)                                               \
	{                                                                      \
		.name = #_name, .psa_lifetime = PSA_KEY_LIFETIME_##_name       \
	}

#define ATTR_ALGO(_name, _class, _algo, _mode, _hash)                          \
	{                                                                      \
		.name = _name,                                                 \
		.smw_algo = (((SMW_ATTR_CLASS_##_class & SMW_ATTR_CLASS_MASK)  \
			      << SMW_ATTR_CLASS_OFFSET) |                      \
			     ((SMW_ATTR_ALGO_##_algo & SMW_ATTR_ALGO_MASK)     \
			      << SMW_ATTR_ALGO_OFFSET) |                       \
			     ((SMW_ATTR_MODE_##_mode & SMW_ATTR_MODE_MASK)     \
			      << SMW_ATTR_MODE_OFFSET) |                       \
			     ((SMW_ATTR_HASH_##_hash & SMW_ATTR_HASH_MASK)     \
			      << SMW_ATTR_HASH_OFFSET))                        \
	}

#define ATTR_ALGO_PSA(_name, _algo)                                            \
	{                                                                      \
		.name = _name, .psa_algo = _algo                               \
	}

#define ATTR_ALGO_CURVE(_name, _class, _algo, _curve, _hash)                   \
	{                                                                      \
		.name = _name,                                                 \
		.smw_algo = (((SMW_ATTR_CLASS_##_class & SMW_ATTR_CLASS_MASK)  \
			      << SMW_ATTR_CLASS_OFFSET) |                      \
			     ((SMW_ATTR_ALGO_##_algo & SMW_ATTR_ALGO_MASK)     \
			      << SMW_ATTR_ALGO_OFFSET) |                       \
			     ((SMW_ATTR_CURVE_##_curve & SMW_ATTR_CURVE_MASK)  \
			      << SMW_ATTR_CURVE_OFFSET) |                      \
			     ((SMW_ATTR_HASH_##_hash & SMW_ATTR_HASH_MASK)     \
			      << SMW_ATTR_HASH_OFFSET))                        \
	}

#define ATTR_ARRAY_FIND_MATCH(_array, _name)                                   \
	({                                                                     \
		typeof(_array[0]) *_elm = (_array);                            \
		typeof(_name) _n = (_name);                                    \
		struct util_attr_info _ret = { 0 };                            \
		while (_elm->name && _n) {                                     \
			if (!strcmp(_elm->name, _n)) {                         \
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
