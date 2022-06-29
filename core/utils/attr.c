// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include "smw_status.h"
#include "debug.h"
#include "attr.h"
#include "utils.h"
#include "tlv.h"

/**
 * fill_attributes() - Fill an attributes structure.
 * @type: Attribute type.
 * @value: Attribute value.
 * @value_size: Length of @value in bytes.
 * @attributes: Pointer to the attributes structure to fill.
 * @tlv_array: Pointer to attribute_tlv structure array.
 * @tlv_array_size: @tlv_array size.
 *
 * Finds the attribute @type into @tlv_array and if found, verify that value is
 * correct.
 * Then store the attribute value into the @attributes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
static int fill_attributes(unsigned char *type, unsigned char *value,
			   unsigned int value_size, void *attributes,
			   const struct attribute_tlv *tlv_array,
			   unsigned int tlv_array_size)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!type)
		goto end;

	for (i = 0; i < tlv_array_size; i++) {
		if (!SMW_UTILS_STRCMP((char *)type,
				      (char *)tlv_array[i].type)) {
			status = tlv_array[i].verify(value_size, value);
			if (status != SMW_STATUS_OK)
				break;

			status = tlv_array[i].store(attributes, value,
						    value_size);
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int read_attributes(const unsigned char *attributes_list,
		    unsigned int attributes_length, void *attributes,
		    const struct attribute_tlv *tlv_array,
		    unsigned int tlv_array_size)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int value_size = 0;
	unsigned char *type = NULL;
	unsigned char *value = NULL;
	const unsigned char *p = attributes_list;
	const unsigned char *end = attributes_list + attributes_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!attributes || !tlv_array)
		goto end;

	if (!attributes_list) {
		status = SMW_STATUS_OK;
		goto end;
	}

	SMW_DBG_PRINTF(DEBUG, "Attributes list:\n");
	SMW_DBG_HEX_DUMP(DEBUG, attributes_list, attributes_length, 4);

	while (p < end) {
		/* Parse attribute */
		status = smw_tlv_read_element(&p, end, &type, &value,
					      &value_size);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing attribute failed\n",
				       __func__);
			break;
		}

		/* Fill attributes structure */
		status = fill_attributes(type, value, value_size, attributes,
					 tlv_array, tlv_array_size);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Bad attribute\n", __func__);
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
