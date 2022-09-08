// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "tlv.h"

int smw_tlv_read_element(const unsigned char **attribute,
			 const unsigned char *end, unsigned char **type,
			 unsigned char **value, unsigned int *value_size)
{
	int status = SMW_STATUS_OK;
	unsigned int j = 1;
	unsigned char *p = (unsigned char *)*attribute;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(attribute && end && type && value && value_size);

	/* Parse type */
	while ((p < end) && (*p != '\0'))
		p++;

	if (p >= end) {
		SMW_DBG_PRINTF(ERROR, "%s: Can't parse type field\n", __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	*type = (unsigned char *)*attribute;
	p++;

	if ((end - p) < SMW_TLV_LENGTH_FIELD_SIZE) {
		SMW_DBG_PRINTF(ERROR,
			       "%s (%d): attributes_length is too small\n",
			       __func__, __LINE__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	/* Parse length */
	*value_size = *p++;
	for (; j < SMW_TLV_LENGTH_FIELD_SIZE; j++) {
		*value_size <<= 8;
		*value_size |= *p++;
	}

	if (!*value_size) {
		SMW_DBG_PRINTF(DEBUG, "%s: Attribute is boolean\n", __func__);
		*value = NULL;
		*attribute = p;
		goto exit;
	}

	if ((unsigned int)(end - p) < *value_size) {
		SMW_DBG_PRINTF(ERROR,
			       "%s (%d): attributes_length is too small\n",
			       __func__, __LINE__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	/* Parse value */
	*value = p;

	/* Update attribute pointer to next element to handle */
	*attribute = p + *value_size;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_tlv_verify_boolean(unsigned int length, unsigned char *value)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!length && !value)
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_tlv_verify_string(unsigned int length, unsigned char *value)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (*(value + length - 1) == '\0')
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_tlv_verify_enumeration(unsigned int length, unsigned char *value)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_tlv_verify_string(length, value);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_tlv_verify_large_numeral(unsigned int length, unsigned char *value)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value && length)
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_tlv_verify_numeral(unsigned int length, unsigned char *value)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value && (length == 1 || length == 2 || length == 4 || length == 8))
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_tlv_verify_variable_length_list(unsigned int length,
					unsigned char *value)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value && length)
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned long long smw_tlv_convert_numeral(unsigned int length,
					   unsigned char *value)
{
	unsigned int i;
	unsigned long long numeral = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value)
		for (i = 0; i < length; i++)
			numeral |= (unsigned long long)value[i]
				   << ((length - 1 - i) * 8);

	return numeral;
}

void smw_tlv_set_element(unsigned char **buffer, const char *type,
			 const unsigned char *value, unsigned int value_size)
{
	unsigned char *p = *buffer;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_UTILS_MEMCPY(p, type, SMW_UTILS_STRLEN(type) + 1);
	p += SMW_UTILS_STRLEN(type) + 1;

	*p = value_size >> 8;
	p++;
	*p = value_size;
	p++;

	if (value && value_size) {
		SMW_UTILS_MEMCPY(p, value, value_size);
		p += value_size;
	}

	*buffer = p;
}

void smw_tlv_set_boolean(unsigned char **buffer, const char *type)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_tlv_set_element(buffer, type, NULL, 0);
}

void smw_tlv_set_string(unsigned char **buffer, const char *type,
			const char *value)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value)
		smw_tlv_set_element(buffer, type, (const unsigned char *)value,
				    (unsigned int)SMW_UTILS_STRLEN(value) + 1);
}

void smw_tlv_set_numeral(unsigned char **buffer, const char *type,
			 uint64_t value)
{
	unsigned char *p = *buffer;

	unsigned int value_size = 1;
	unsigned int size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value >> 32)
		value_size = 8;
	else if (value >> 16)
		value_size = 4;
	else if (value >> 8)
		value_size = 2;

	SMW_UTILS_MEMCPY(p, type, SMW_UTILS_STRLEN(type) + 1);
	p += SMW_UTILS_STRLEN(type) + 1;

	*p = value_size >> 8;
	p++;
	*p = value_size;
	p++;

	size = value_size;

	while (size) {
		*(p + size - 1) = value;
		value >>= 8;
		size--;
	}

	p += value_size;

	*buffer = p;
}

void smw_tlv_set_type(unsigned char **buffer, const char *type)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_tlv_set_element(buffer, type, NULL, 0);
}

void smw_tlv_set_length(unsigned char *element, unsigned char *end)
{
	unsigned char *p;
	unsigned int value_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = element + SMW_UTILS_STRLEN((char *)element) + 1;

	value_size = (unsigned int)(end - p - SMW_TLV_LENGTH_FIELD_SIZE);

	*p = value_size >> 8;
	p++;
	*p = value_size;
}
