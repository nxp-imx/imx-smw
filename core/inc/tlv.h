/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
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
 *
 * Length and value must be set.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int smw_tlv_verify_large_numeral(unsigned int length, unsigned char *value);
