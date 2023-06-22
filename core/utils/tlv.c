// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "tlv.h"

int smw_tlv_read_element(const unsigned char **element,
			 const unsigned char *end, unsigned char **type,
			 unsigned char **value, unsigned int *value_size)
{
	int status = SMW_STATUS_OK;
	unsigned int j = 1;
	unsigned char *p = (unsigned char *)*element;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(element && end && type && value && value_size);

	/* Parse type */
	while ((p < end) && (*p != '\0'))
		p++;

	if (p >= end) {
		SMW_DBG_PRINTF(ERROR, "%s: Can't parse type field\n", __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	*type = (unsigned char *)*element;
	p++;

	if ((end - p) < SMW_TLV_LENGTH_FIELD_SIZE) {
		SMW_DBG_PRINTF(ERROR, "%s (%d): Buffer is too small\n",
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
		SMW_DBG_PRINTF(DEBUG, "%s: Element length is 0\n", __func__);
		*value = NULL;
		*element = p;
		goto exit;
	}

	if ((unsigned int)(end - p) < *value_size) {
		SMW_DBG_PRINTF(ERROR, "%s (%d): Buffer is too small\n",
			       __func__, __LINE__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	/* Parse value */
	*value = p;

	/* Update element pointer to next element to handle */
	*element = p + *value_size;

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
	SMW_DBG_TRACE_FUNCTION_CALL;

	int status = smw_tlv_verify_string(length, value);

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
	unsigned int i = 0;
	unsigned long long numeral = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value)
		for (; i < length; i++)
			numeral |= (unsigned long long)value[i]
				   << ((length - 1 - i) * 8);

	return numeral;
}

void smw_tlv_set_element(unsigned char **buffer, const char *type,
			 const unsigned char *value, unsigned int value_size)
{
	unsigned char *p = *buffer;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_UTILS_MEMCPY(p, type, SMW_UTILS_STRLEN(type));
	p += SMW_UTILS_STRLEN(type);
	*p++ = 0;

	*p = (value_size >> 8) & UCHAR_MAX;
	p++;
	*p = value_size & UCHAR_MAX;
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
	size_t length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (value) {
		length = SMW_UTILS_STRLEN(value);
		if (length < UINT_MAX - 1) {
			length++;
			smw_tlv_set_element(buffer, type,
					    (const unsigned char *)value,
					    length);
		}
	}
}

unsigned int smw_tlv_numeral_length(uint64_t value)
{
	unsigned int length = 1;

	if (value >> 32)
		length = 8;
	else if (value >> 16)
		length = 4;
	else if (value >> 8)
		length = 2;

	return length;
}

void smw_tlv_set_numeral(unsigned char **buffer, const char *type,
			 uint64_t value)
{
	unsigned char *p = *buffer;

	unsigned int value_size = 0;
	unsigned int size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	value_size = smw_tlv_numeral_length(value);

	SMW_UTILS_MEMCPY(p, type, SMW_UTILS_STRLEN(type));
	p += SMW_UTILS_STRLEN(type);
	*p++ = 0;

	*p = value_size >> 8;
	p++;
	*p = value_size;
	p++;

	size = value_size;

	while (size) {
		*(p + size - 1) = value & UCHAR_MAX;
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
	unsigned char *p = NULL;
	size_t value_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = element + SMW_UTILS_STRLEN((char *)element) + 1;

	if (SUB_OVERFLOW((uintptr_t)end, (uintptr_t)p, &value_size))
		value_size = 0;

	if (value_size < SMW_TLV_LENGTH_FIELD_SIZE)
		value_size = 0;
	else
		value_size -= SMW_TLV_LENGTH_FIELD_SIZE;

	*p = (value_size >> 8) & UCHAR_MAX;
	p++;
	*p = value_size & 0xFF;
}
