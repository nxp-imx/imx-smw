// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "debug.h"
#include "tlv.h"
#include "utils.h"

#include "common.h"

struct perm_algo_param {
	const char *str;
	unsigned int shift;
	unsigned int mask;
	unsigned int min_bit;
	int (*to_value)(unsigned int *algo, const unsigned char *value,
			unsigned int value_size,
			const struct perm_algo_param *param);
	size_t (*to_str)(unsigned char **str, size_t str_length,
			 unsigned int algo,
			 const struct perm_algo_param *param);
};

#define KEY_USAGE(_smw, _ele, _restricted)                                     \
	{                                                                      \
		.str = _smw##_STR, .ele = HSM_KEY_USAGE_##_ele,                \
		.restricted = _restricted                                      \
	}

/**
 * struct - Key usage
 * @str: SMW usage name used for TLV encoding.
 * @ele: ELE key usage value.
 * @restricted: Is usage restricted to an algorithm.
 */
static const struct {
	const char *str;
	hsm_key_usage_t ele;
	bool restricted;
} key_usage[] = { KEY_USAGE(EXPORT, EXPORT, false),
		  KEY_USAGE(ENCRYPT, ENCRYPT, true),
		  KEY_USAGE(DECRYPT, DECRYPT, true),
		  KEY_USAGE(SIGN_MESSAGE, SIGN_MSG, true),
		  KEY_USAGE(VERIFY_MESSAGE, VERIFY_MSG, true),
		  KEY_USAGE(SIGN_HASH, SIGN_HASH, true),
		  KEY_USAGE(VERIFY_HASH, VERIFY_HASH, true),
		  KEY_USAGE(DERIVE, DERIVE, true) };

#define KEY_ALGO(_smw, _ele)                                                   \
	{                                                                      \
		.str = _smw##_STR, .value = _ele                               \
	}

static const struct {
	const char *str;
	unsigned int value;
} hash_algos[] = { KEY_ALGO(SHA_1, 0x5),   KEY_ALGO(SHA_224, 0x8),
		   KEY_ALGO(SHA_256, 0x9), KEY_ALGO(SHA_384, 0xA),
		   KEY_ALGO(SHA_512, 0xB), KEY_ALGO(ANY, 0xFF) };

static int perm_algo_hash_val(unsigned int *algo, const unsigned char *value,
			      unsigned int value_size,
			      const struct perm_algo_param *param)
{
	(void)value_size;

	size_t i = 0;

	SMW_DBG_PRINTF(DEBUG, "%s(%d) HASH=%s\n", __func__, __LINE__, value);

	for (; i < ARRAY_SIZE(hash_algos); i++) {
		if (SMW_UTILS_STRCMP(hash_algos[i].str, (char *)value))
			continue;

		if (hash_algos[i].value > param->mask)
			return false;

		*algo = SET_CLEAR_MASK(*algo,
				       hash_algos[i].value << param->shift,
				       param->mask << param->shift);

		SMW_DBG_PRINTF(DEBUG, "%s(%d) algo=0x%08X\n", __func__,
			       __LINE__, *algo);

		return true;
	}

	return false;
}

static int perm_algo_length_val(unsigned int *algo, const unsigned char *value,
				unsigned int value_size,
				const struct perm_algo_param *param)
{
	unsigned long long numeral = 0;
	unsigned int len = 0;

	numeral = smw_tlv_convert_numeral(value_size, (unsigned char *)value);
	if (numeral > UINT32_MAX)
		return false;

	len = numeral;
	if (len > param->mask)
		return false;

	*algo = SET_CLEAR_MASK(*algo, len << param->shift,
			       param->mask << param->shift);

	SMW_DBG_PRINTF(DEBUG, "%s(%d) algo=0x%08X\n", __func__, __LINE__,
		       *algo);

	return true;
}

static int perm_algo_minlength_val(unsigned int *algo,
				   const unsigned char *value,
				   unsigned int value_size,
				   const struct perm_algo_param *param)
{
	if (perm_algo_length_val(algo, value, value_size, param)) {
		*algo |= param->min_bit;

		SMW_DBG_PRINTF(DEBUG, "%s(%d) algo=0x%08X\n", __func__,
			       __LINE__, *algo);
		return true;
	}

	return false;
}

static size_t perm_algo_hash_str(unsigned char **str, size_t str_length,
				 unsigned int algo,
				 const struct perm_algo_param *param)
{
	size_t out_len = 0;
	size_t i = 0;
	unsigned int hash_algo = 0;

	hash_algo = (algo >> param->shift) & param->mask;

	if (hash_algo) {
		for (; i < ARRAY_SIZE(hash_algos); i++) {
			if (hash_algos[i].value != hash_algo)
				continue;

			SMW_DBG_PRINTF(DEBUG, "%s(%d) %s=%s\n", __func__,
				       __LINE__, param->str, hash_algos[i].str);

			out_len = SMW_UTILS_STRLEN(hash_algos[i].str) + 1;

			if (SMW_TLV_ELEMENT_LENGTH(param->str, out_len,
						   out_len)) {
				out_len = SIZE_MAX;
				break;
			}

			if (*str) {
				if (str_length >= out_len)
					smw_tlv_set_string(str, param->str,
							   hash_algos[i].str);
				else
					out_len = SIZE_MAX;
			}

			break;
		}
	}

	return out_len;
}

static size_t perm_algo_length_str(unsigned char **str, size_t str_length,
				   unsigned int algo,
				   const struct perm_algo_param *param)
{
	uint64_t algo_length = 0;
	size_t out_len = 0;

	if (algo & param->min_bit)
		return out_len;

	algo_length = (algo >> param->shift) & param->mask;

	if (algo_length) {
		out_len = smw_tlv_numeral_length(algo_length);
		if (SMW_TLV_ELEMENT_LENGTH(param->str, out_len, out_len))
			return SIZE_MAX;

		SMW_DBG_PRINTF(DEBUG, "%s(%d) %s=%lu\n", __func__, __LINE__,
			       param->str, algo_length);

		if (*str) {
			if (str_length >= out_len)
				smw_tlv_set_numeral(str, param->str,
						    algo_length);
			else
				out_len = SIZE_MAX;
		}
	}

	return out_len;
}

static size_t perm_algo_minlength_str(unsigned char **str, size_t str_length,
				      unsigned int algo,
				      const struct perm_algo_param *param)
{
	size_t out_len = 0;

	if (algo & param->min_bit)
		out_len = perm_algo_length_str(str, str_length,
					       algo & ~param->min_bit, param);

	return out_len;
}

#define PERMITTED_ALGO_HMAC_ANY_HASH		   (PERMITTED_ALGO_HMAC_SHA256 | 0xFF)
#define PERMITTED_ALGO_ECDSA_ANY_HASH		   (PERMITTED_ALGO_ECDSA_SHA256 | 0xFF)
#define PERMITTED_ALGO_RSA_PKCS1_V15_ANY_HASH	   (0x060002FF)
#define PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_ANY_HASH (0x060003FF)

#define PERM_ALGO_PARAM(_name, _shift, _mask, _min_bit, _to_value, _to_str)    \
	{                                                                      \
		.str = _name##_STR, .shift = _shift, .mask = _mask,            \
		.min_bit = _min_bit, .to_value = _to_value, .to_str = _to_str  \
	}

static const struct perm_algo_param perm_hmac_algo[] = {
	PERM_ALGO_PARAM(HASH, 0, 0xFF, 0, &perm_algo_hash_val,
			&perm_algo_hash_str),
	PERM_ALGO_PARAM(LENGTH, 16, 0x3F, BIT(15), &perm_algo_length_val,
			&perm_algo_length_str),
	PERM_ALGO_PARAM(MIN_LENGTH, 16, 0x3F, BIT(15), &perm_algo_minlength_val,
			&perm_algo_minlength_str),
	{ 0 }
};

static const struct perm_algo_param perm_cmac_algo[] = {
	PERM_ALGO_PARAM(LENGTH, 16, 0x3F, BIT(15), &perm_algo_length_val,
			&perm_algo_length_str),
	PERM_ALGO_PARAM(MIN_LENGTH, 16, 0x3F, BIT(15), &perm_algo_minlength_val,
			&perm_algo_minlength_str),
	{ 0 }
};

static const struct perm_algo_param perm_hash_algo[] = {
	PERM_ALGO_PARAM(HASH, 0, 0xFF, 0, &perm_algo_hash_val,
			&perm_algo_hash_str),
	{ 0 }
};

#define PERM_ALGO(_name, _base, _length_mask, _params)                         \
	{                                                                      \
		.str = _name##_STR, .algo_base = PERMITTED_ALGO_##_base,       \
		.length_mask = _length_mask, .params = _params                 \
	}

static const struct {
	const char *str;
	int algo_base;
	int length_mask;
	const struct perm_algo_param *params;
} perm_algos[] = {
	PERM_ALGO(HMAC, HMAC_ANY_HASH, (0x3F << 16) | BIT(15), perm_hmac_algo),
	PERM_ALGO(CMAC, CMAC, (0x3F << 16) | BIT(15), perm_cmac_algo),
	PERM_ALGO(CTR, CTR, 0, NULL),
	PERM_ALGO(ECB_NO_PADDING, ECB_NO_PADDING, 0, NULL),
	PERM_ALGO(CBC_NO_PADDING, CBC_NO_PADDING, 0, NULL),
	PERM_ALGO(ALL_CIPHER, ALL_CIPHER, 0, NULL),
	PERM_ALGO(CCM, CCM, 0, NULL),
	PERM_ALGO(RSA_PKCS1V15, RSA_PKCS1_V15_ANY_HASH, 0, perm_hash_algo),
	PERM_ALGO(RSA_PSS, RSA_PKCS1_PSS_MGF1_ANY_HASH, 0, perm_hash_algo),
	PERM_ALGO(ECDSA, ECDSA_ANY_HASH, 0, perm_hash_algo),
	PERM_ALGO(ALL_AEAD, ALL_AEAD, 0, NULL)
};

static int convert_algo_param(unsigned int *algo,
			      const struct perm_algo_param *params, char *type,
			      const unsigned char *value,
			      unsigned int value_size)
{
	const struct perm_algo_param *param = params;

	while (param->str) {
		if (!SMW_UTILS_STRCMP(param->str, type)) {
			SMW_DBG_PRINTF(DEBUG, "%s(%d) Param=%s\n", __func__,
				       __LINE__, type);

			return param->to_value(algo, value, value_size, param);
		}

		param++;
	}

	return false;
}

/**
 * set_key_algo_params() - Verify and parse TLV algorithm parameters
 * @buffer: Buffer to parse
 * @end: End of @buffer
 * @algo_str: Algorithm TLV value
 * @algo: ELE algorithm value corresponding
 * @actual_policy: Actual key policy parsed
 *
 * First verify if the algorithm is supported by ELE.
 * Then read and parse all algorithm's parameters if any given by @buffer.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_KEY_POLICY_WARNING_IGNORED - Algorithm or parameter(s) ignored
 * SMW_STATUS_KEY_POLICY_ERROR           - Error in the parameter encoding
 * Other errors.
 */
static int set_key_algo_params(const unsigned char *buffer,
			       const unsigned char *end, char *algo_str,
			       unsigned int *algo,
			       unsigned char **actual_policy)
{
	int status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;

	int ignored = 0;
	const struct perm_algo_param *algo_params = NULL;
	const unsigned char *p = buffer;
	unsigned int value_size = 0;
	char *type = NULL;
	unsigned char *value = NULL;
	unsigned char *out_policy = *actual_policy;
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*algo = 0;

	for (; i < ARRAY_SIZE(perm_algos); i++) {
		if (!SMW_UTILS_STRCMP(perm_algos[i].str, algo_str)) {
			algo_params = perm_algos[i].params;
			*algo = perm_algos[i].algo_base;
			break;
		}
	}

	/* Algorithm not defined, return */
	if (!*algo) {
		SMW_DBG_PRINTF(DEBUG, "%s: ALGO=%s ignored\n", __func__,
			       algo_str);
		goto exit;
	}

	/*
	 * Build the output algorithm/parameters attributes correctly
	 * parsed.
	 * Step 1. Set the new algorithm TLV entry, the L value may be
	 *         changed to add the algorithm's parameters.
	 */
	smw_tlv_set_string(&out_policy, ALGO_STR, algo_str);

	/* Check if parameters are expected for this algorithm */
	if (!algo_params) {
		SMW_DBG_PRINTF(DEBUG, "%s: ALGO=%s no parameter supported\n",
			       __func__, algo_str);

		if (p >= end)
			status = SMW_STATUS_OK;
		p = end;
	} else if (p >= end) {
		SMW_DBG_PRINTF(DEBUG, "%s: ALGO=%s no parameter defined\n",
			       __func__, algo_str);
		status = SMW_STATUS_OK;
	}

	while (p < end) {
		status = smw_tlv_read_element(&p, end, (unsigned char **)&type,
					      &value, &value_size);

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing parameters failed\n",
				       __func__);

			if (status == SMW_STATUS_INVALID_PARAM)
				status = SMW_STATUS_KEY_POLICY_ERROR;

			goto exit;
		}

		if (convert_algo_param(algo, algo_params, type, value,
				       value_size)) {
			/*
			 * Build the output algorithm/parameters attributes
			 * correctly parsed.
			 * Step 2. Set the parameter TLV entry
			 *         Increase the final algorithm length (L field)
			 */
			smw_tlv_set_element(&out_policy, type, value,
					    value_size);
		} else {
			ignored++;
		}
	}

	/*
	 * Build the output algorithm/parameters attributes correctly
	 * parsed.
	 * Step 3. Set the L field value of the algorithm TLV entry.
	 */
	smw_tlv_set_length(*actual_policy, out_policy);

	if (ignored)
		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;

	*actual_policy = out_policy;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * convert_usage_to_value() - Convert SMW to ELE key usage value
 * @value: String value to convert
 * @usage: ELE key usage bitmask
 *
 * Return:
 * True if value supported, otherwise false.
 */
static bool convert_usage_to_value(const char *value, hsm_key_usage_t *usage)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(key_usage); i++) {
		if (!SMW_UTILS_STRCMP(key_usage[i].str, value)) {
			SMW_DBG_PRINTF(DEBUG, "Key usage: %s\n", value);
			*usage |= key_usage[i].ele;
			return true;
		}
	}

	return false;
}

/**
 * key_algo_to_string() - Convert ELE key algorithm value(s) to SMW's policy
 *                        string
 * @str: Pointer to string value of @algo bitmask
 * @length: Maximum length of the @str
 * @algo: ELE key algo bitmask
 *
 * Return:
 * If @str is NULL, the expected length of @str
 * If @str is not NULL, the length of @str built
 * -1 in case of error (@str's length too small
 */
static size_t key_algo_to_string(unsigned char **str, size_t length,
				 hsm_permitted_algo_t algo)
{
	const struct perm_algo_param *algo_params = NULL;
	const char *algo_str = NULL;
	unsigned char *p = *str;
	size_t out_len = 0;
	size_t rem_len = length;
	size_t algo_len = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(perm_algos); i++) {
		if ((algo & perm_algos[i].algo_base) ==
		    (algo & ~perm_algos[i].length_mask)) {
			algo_str = perm_algos[i].str;
			algo_params = perm_algos[i].params;
			break;
		}
	}

	if (!algo_str)
		goto exit;

	SMW_DBG_PRINTF(DEBUG, "Key algo %s\n", algo_str);

	algo_len = SMW_UTILS_STRLEN(algo_str) + 1;
	if (SMW_TLV_ELEMENT_LENGTH(ALGO_STR, algo_len, algo_len)) {
		out_len = SIZE_MAX;
		goto exit;
	}

	if (p) {
		if (rem_len >= algo_len) {
			smw_tlv_set_string(&p, ALGO_STR, algo_str);
			rem_len -= algo_len;
		} else {
			out_len = SIZE_MAX;
			goto exit;
		}
	}

	out_len += algo_len;

	while (algo_params && algo_params->str) {
		algo_len = algo_params->to_str(&p, rem_len, algo, algo_params);

		if (algo_len == SIZE_MAX) {
			out_len = SIZE_MAX;
			goto exit;
		} else {
			if (ADD_OVERFLOW(out_len, algo_len, &out_len)) {
				out_len = SIZE_MAX;
				goto exit;
			}
		}

		algo_params++;
	}

	if (p)
		smw_tlv_set_length(p - out_len, p);

exit:
	if (out_len != SIZE_MAX && *str)
		*str = p;

	SMW_DBG_PRINTF(DEBUG, "%s return length %zu\n", __func__, out_len);
	return out_len;
}

/**
 * key_usage_algo_to_string() - Convert ELE key usage and algorithm value(s) to
 *                              SMW's policy string
 * @str: Pointer to string value of @usage and @algo bitmask
 * @length: Maximum length of the @str
 * @usage: ELE key usage bitmask
 * @algo: ELE key algo bitmask
 *
 * Return:
 * If @str is NULL, the expected length of @str
 * If @str is not NULL, the length of @str built
 * -1 in case of error (@str's length too small
 */
static size_t key_usage_algo_to_string(unsigned char **str, size_t length,
				       hsm_key_usage_t usage,
				       hsm_permitted_algo_t algo)
{
	unsigned char *p = *str;
	size_t out_len = 0;
	size_t rem_len = length;
	size_t usage_len = 0;
	size_t algo_len = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(key_usage); i++) {
		if (!(usage & key_usage[i].ele))
			continue;

		SMW_DBG_PRINTF(DEBUG, "Key usage: %s\n", key_usage[i].str);

		usage_len = SMW_UTILS_STRLEN(key_usage[i].str) + 1;
		if (SMW_TLV_ELEMENT_LENGTH(USAGE_STR, usage_len, usage_len)) {
			out_len = SIZE_MAX;
			break;
		}

		if (p) {
			if (rem_len >= usage_len) {
				smw_tlv_set_string(&p, USAGE_STR,
						   key_usage[i].str);
				rem_len -= usage_len;
			} else {
				out_len = SIZE_MAX;
				break;
			}
		}

		if (key_usage[i].restricted) {
			/* Get the expected algo string length */
			algo_len = key_algo_to_string(&p, rem_len, algo);
			if (algo_len == SIZE_MAX)
				break;

			usage_len += algo_len;

			if (p) {
				rem_len -= algo_len;
				smw_tlv_set_length(p - usage_len, p);
			}
		}

		if (ADD_OVERFLOW(out_len, usage_len, &out_len)) {
			out_len = SIZE_MAX;
			break;
		}
	}

	if (out_len != SIZE_MAX && *str)
		*str = p;

	SMW_DBG_PRINTF(DEBUG, "%s return length %zu\n", __func__, out_len);
	return out_len;
}

/**
 * set_key_algo() - Parse the key usage's algorithm
 * @buffer: Buffer to parse
 * @end: End of @buffer
 * @ele_algo: ELE permitted algorithm (in/out)
 * @actual_policy: Actual policy correctly parsed
 *
 * Read and parse all algorithms and associated parameters if any of
 * the key usage TLV given in @buffer.
 *
 * Return:
 * SMW_STATUS_OK                         - Success
 * SMW_STATUS_KEY_POLICY_WARNING_IGNORED - One of the Usage's algorithm ignored
 * SMW_STATUS_KEY_POLICY_ERROR           - Error in the key usage encoding
 * Other errors.
 */
static int set_key_algo(const unsigned char *buffer, const unsigned char *end,
			hsm_permitted_algo_t *ele_algo,
			unsigned char **actual_policy)
{
	int status = SMW_STATUS_KEY_POLICY_ERROR;

	const unsigned char *p = buffer;
	const unsigned char *q = NULL;
	const unsigned char *q_end = NULL;
	unsigned int value_size = 0;
	unsigned char *type = NULL;
	unsigned char *value = NULL;
	char *algo_str = NULL;
	unsigned int algo = 0;
	int ignored = 0;
	unsigned char *out_policy = *actual_policy;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (p < end) {
		status = smw_tlv_read_element(&p, end, &type, &value,
					      &value_size);

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing algorithm failed\n",
				       __func__);

			if (status == SMW_STATUS_INVALID_PARAM)
				status = SMW_STATUS_KEY_POLICY_ERROR;

			goto exit;
		}

		if (SMW_UTILS_STRCMP((char *)type, ALGO_STR)) {
			ignored++;
			continue;
		}

		algo_str = (char *)value;

		/*
		 * Adjust the string and its length to the parameter of
		 * the algorithm if any.
		 */
		q = value + SMW_UTILS_STRLEN(algo_str) + 1;
		q_end = value + value_size;
		status = set_key_algo_params(q, q_end, algo_str, &algo,
					     &out_policy);

		if (status != SMW_STATUS_OK &&
		    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
			goto exit;

		/*
		 * If the parsing of the algorithm and its parameters is
		 * correct or partially correct, 2 cases to consider:
		 *  - No permitted algorithm set
		 *     => Set the permitted algorithm and fill the actual
		 *        algorithm/parameters attributes to be returned.
		 *        Continue algorithm/parameters parsing but ignore.
		 *  - Permitted algorithm set
		 *     => If this is the same as the one parsed, continue
		 *     => If this is not the same, increase ignored counter and
		 *        continue.
		 *
		 * If the parsing of the algorithm and its parameters results
		 * in an error. Stop here and exit in error.
		 */
		if (!*ele_algo)
			(void)SET_OVERFLOW(algo, *ele_algo);

		if (algo != *ele_algo) {
			out_policy = *actual_policy;
			ignored++;
		} else {
			*actual_policy = out_policy;
		}

		if (status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
			ignored++;
	}

	if (ignored)
		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_set_key_policy(const unsigned char *policy, unsigned int policy_len,
		       hsm_key_usage_t *ele_usage,
		       hsm_permitted_algo_t *ele_algo,
		       unsigned char **actual_policy,
		       unsigned int *actual_policy_len)
{
	int status = SMW_STATUS_KEY_POLICY_ERROR;

	int ignored = 0;
	const unsigned char *p = policy;
	const unsigned char *end = p + policy_len;
	unsigned int value_size = 0;
	unsigned char *type = NULL;
	unsigned char *value = NULL;
	char *usage_str = NULL;
	unsigned char *out_policy = NULL;
	unsigned char *out_usage = NULL;

	if (!policy || !policy_len)
		return status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (SMW_TLV_ELEMENT_LENGTH(POLICY_STR, policy_len, *actual_policy_len))
		goto exit;

	*actual_policy = SMW_UTILS_MALLOC(*actual_policy_len);
	if (!*actual_policy) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	*ele_usage = 0;

	/*
	 * Build the output policy attribute
	 * Step 1. Set the new policy TLV entry, the L value may be
	 *         changed to add the key usage(s) and its algorithm/parameters.
	 */
	out_policy = *actual_policy;
	smw_tlv_set_type(&out_policy, POLICY_STR);

	while (p < end) {
		status = smw_tlv_read_element(&p, end, &type, &value,
					      &value_size);

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing policy failed\n",
				       __func__);
			goto exit;
		}

		if (SMW_UTILS_STRCMP((char *)type, USAGE_STR))
			continue;

		usage_str = (char *)value;

		if (!convert_usage_to_value(usage_str, ele_usage)) {
			ignored++;
			continue;
		}

		/*
		 * Build the output usage attribute
		 * Step 1. Set the new usage TLV entry, the L value may be
		 *         changed to add the algorithm and its parameters.
		 */
		out_usage = out_policy;
		smw_tlv_set_string(&out_policy, USAGE_STR, usage_str);

		/* Parse the permitted algorithms if any */
		if (SMW_UTILS_STRLEN(usage_str) + 1 < value_size) {
			value += SMW_UTILS_STRLEN(usage_str) + 1;
			value_size -= SMW_UTILS_STRLEN(usage_str) + 1;

			status = set_key_algo(value, value + value_size,
					      ele_algo, &out_policy);
			if (status != SMW_STATUS_OK &&
			    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
				goto exit;

			if (status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
				ignored++;
		}

		/*
		 * Build the output usage attribute correctly parsed.
		 * Step 3. Set the L field value of the usage TLV entry.
		 */
		smw_tlv_set_length(out_usage, out_policy);
	}

	/*
	 * Build the output policy attribute
	 * Step 3. Set the L field value of the policy TLV element.
	 */
	smw_tlv_set_length(*actual_policy, out_policy);

	if (ignored)
		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;

	SMW_DBG_ASSERT((uintptr_t)out_policy - (uintptr_t)*actual_policy <=
		       *actual_policy_len);
	*actual_policy_len = out_policy - *actual_policy;

exit:
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		if (*actual_policy) {
			SMW_UTILS_FREE(*actual_policy);
			*actual_policy = NULL;
		}

		*actual_policy_len = 0;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_get_key_policy(unsigned char **policy, unsigned int *policy_len,
		       hsm_key_usage_t ele_usage, hsm_permitted_algo_t ele_algo)
{
	int status = SMW_STATUS_INVALID_PARAM;

	size_t usage_str_len = 0;
	unsigned char *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!policy || !policy_len)
		goto exit;

	/* Get the expected usage(s) and algo string length */
	usage_str_len = key_usage_algo_to_string(&p, usage_str_len, ele_usage,
						 ele_algo);
	if (usage_str_len == SIZE_MAX) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	/* Calculate policy length and allocate the policy string */
	if (SMW_TLV_ELEMENT_LENGTH(POLICY_STR, usage_str_len, *policy_len)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	*policy = SMW_UTILS_CALLOC(1, *policy_len);
	if (!*policy) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	p = *policy;
	smw_tlv_set_type(&p, POLICY_STR);

	/* Get the expected usage(s) and algo string */
	usage_str_len = key_usage_algo_to_string(&p, usage_str_len, ele_usage,
						 ele_algo);
	if (usage_str_len == SIZE_MAX) {
		status = SMW_STATUS_OPERATION_FAILURE;
	} else {
		smw_tlv_set_length(*policy, p);
		status = SMW_STATUS_OK;
	}

exit:
	if (status != SMW_STATUS_OK) {
		if (policy && *policy) {
			SMW_UTILS_FREE(*policy);

			*policy = NULL;
		}

		if (policy_len)
			*policy_len = 0;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
