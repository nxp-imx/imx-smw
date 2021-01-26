// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "tlv_encode.h"

CK_RV tlv_encode_boolean(struct smw_tlv *tlv, const char *type)
{
	size_t len_add;

	/*
	 * Boolean is TLV encode with:
	 *   - Type = null terminated string @type
	 *   - Length = 2 bytes of 0
	 *   - Value is not set
	 */
	len_add = strlen(type) + 3;
	if (!tlv->string) {
		tlv->string = malloc(len_add);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		tlv->length_max = len_add;
	} else if (tlv->length_max < tlv->length + len_add) {
		tlv->string = realloc(tlv->string, tlv->length_max + len_add);
		if (!tlv->string)
			return CKR_HOST_MEMORY;

		tlv->length_max += len_add;
	}

	/* Add the Type @type to current tlv string */
	memcpy(&tlv->string[tlv->length], type, strlen(type));
	tlv->length += strlen(type);

	/* Set the Type null terminated character */
	tlv->string[tlv->length++] = 0;

	/* Set the 2 bytes of Length = 0 */
	tlv->string[tlv->length++] = 0;
	tlv->string[tlv->length++] = 0;

	return CKR_OK;
}

void tlv_encode_free(struct smw_tlv *tlv)
{
	if (tlv->string)
		free(tlv->string);
}
