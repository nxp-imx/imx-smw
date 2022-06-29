/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

/* TLV defines */
#define SMW_TLV_LENGTH_FIELD_SIZE 2 /* TLV length encoded with 2 bytes */

/**
 * smw_tlv_read_element() - Read one Type-Length-Value encoded element.
 * @attribute: [in/out] pointer to the element to read and pointing to the next
 *                      element when function returns.
 * @end: Pointer to @attribute end address.
 * @type: Pointer to type buffer.
 * @value: Pointer to value buffer.
 * @value_size: Pointer to value buffer size (in bytes).
 *
 * This function reads one TLV encoded buffer.
 * TLV format is:
 *  - Type: String null terminated.
 *  - Length: Size of value in bytes (encoded as a number on 2 bytes).
 *  - Value: Byte stream.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- Failed to read buffer.
 */
int smw_tlv_read_element(const unsigned char **attribute,
			 const unsigned char *end, unsigned char **type,
			 unsigned char **value, unsigned int *value_size);

/**
 * smw_tlv_verify_boolean() - Verify that TLV length and value correspond to
 *                            boolean type.
 * @length: Length of @value in bytes.
 * @value: Value buffer.
 *
 * Length must be 0 and value must be NULL.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int smw_tlv_verify_boolean(unsigned int length, unsigned char *value);

/**
 * smw_tlv_verify_string() - Verify that TLV length and value correspond to
 *                           string type.
 * @length: Length of @value in bytes.
 * @value: Value buffer.
 *
 * Value must be a null-terminated string.
 * Length must be the length of @value including the null character.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int smw_tlv_verify_string(unsigned int length, unsigned char *value);

/**
 * smw_tlv_verify_enumeration() - Verify that TLV length and value correspond to
 *                                enumeration type.
 * @length: Length of @value in bytes.
 * @value: Value buffer.
 *
 * Enumeration type is treated as string type.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int smw_tlv_verify_enumeration(unsigned int length, unsigned char *value);

/**
 * smw_tlv_verify_large_numeral() - Verify that TLV length and value correspond
 *                                  to large numeral type.
 * @length: Length of @value in bytes.
 * @value: Value buffer.
 *
 * Length and value must be set.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int smw_tlv_verify_large_numeral(unsigned int length, unsigned char *value);

/**
 * smw_tlv_verify_numeral() - Verify that TLV length and value correspond to
 *                            numeral type.
 * @length: Length of @value in bytes.
 * @value: Value buffer.
 *
 * Length must be 1, 2, 4 or 8. Value must be set.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int smw_tlv_verify_numeral(unsigned int length, unsigned char *value);

/**
 * smw_tlv_verify_variable_length_list() - Verify that TLV length and value correspond
 *                                         to variable-length list type.
 * @length: Length of @value in bytes.
 * @value: Value buffer.
 *
 * Length and value must be set.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int smw_tlv_verify_variable_length_list(unsigned int length,
					unsigned char *value);

/**
 * smw_tlv_convert_numeral() - Convert TLV numeral value in uint64_t.
 * @length: Length of @value in bytes.
 * @value: Value buffer.
 *
 * Return:
 * 0	- @length is 0 or @value is NULL.
 * Converted integer.
 */
unsigned long long smw_tlv_convert_numeral(unsigned int length,
					   unsigned char *value);

/**
 * smw_tlv_set_string() - Encode TLV string in a buffer.
 * @buffer: Pointer to the buffer.
 * @type: Type of the string.
 * @value: String to be encoded.
 *
 * Type and value must be null-terminated strings.
 *
 * Return:
 * None.
 */
void smw_tlv_set_string(unsigned char **buffer, char *type, char *value);
