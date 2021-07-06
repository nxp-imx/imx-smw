/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __ATTR_H__
#define __ATTR_H__

/**
 * struct attribute_tlv - Attributes handler.
 * @type: Attribute type.
 * @verify: Verification function appropriate to the attribute type.
 * @store: Store function appropriate to the attribute type.
 *
 * This structure provides functions to verify the kind of attribute type
 * (boolean, enumeration, string, numeral) and store the value.
 */
struct attribute_tlv {
	const unsigned char *type;
	int (*verify)(unsigned int length, unsigned char *value);
	int (*store)(void *attributes, unsigned char *value,
		     unsigned int length);
};

/**
 * read_attributes() - Read key_attributes_list buffer.
 * @attributes_list: List of attributes buffer to read.
 * @attributes_length: Attributes buffer size (bytes).
 * @attributes: Pointer to the attributes structure to fill.
 * @tlv_array: Pointer to attribute_tlv structure array.
 * @tlv_array_size: @tlv_array size.
 *
 * This function reads a list of attributes parsed by smw_tlv_read_element()
 * function and fill @attributes structure using fill_attributes() function.
 * @attributes_list is encoded with TLV encoding scheme:
 * The ‘Type’ field is encoded as an ASCII string terminated with the null
 * character.
 * The ‘Length’ field is encoded with two bytes.
 * The ‘Value’ field is a byte stream that contains the data.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
int read_attributes(const unsigned char *attributes_list,
		    unsigned int attributes_length, void *attributes,
		    const struct attribute_tlv *tlv_array,
		    unsigned int tlv_array_size);

#endif /* __ATTR_H__ */
