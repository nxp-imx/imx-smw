// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "builtin_macros.h"

#include "json_types.h"
#include "json_util.h"
#include "util.h"
#include "util_tlv.h"

struct tlv {
	uint8_t tag;
	size_t length;

	bool new_buf;
	enum t_data_type val_type;
	union {
		uint8_t *buf;
		uint64_t numeral;
	};
};

// Magic value is "edgelockenclaveimport"
const uint8_t ELE_KEY_IMPORT_VAL_MAGIC[] = { 0x65, 0x64, 0x67, 0x65, 0x6c, 0x6f,
					     0x63, 0x6b, 0x65, 0x6e, 0x63, 0x6c,
					     0x61, 0x76, 0x65, 0x69, 0x6d, 0x70,
					     0x6f, 0x72, 0x74 };

#define ELE_KEY_IMPORT_TAG_MAGIC	 0x40
#define ELE_KEY_IMPORT_TAG_KEY_ID	 0x41
#define ELE_KEY_IMPORT_TAG_KEY_ALGO	 0x42
#define ELE_KEY_IMPORT_TAG_KEY_USAGE	 0x43
#define ELE_KEY_IMPORT_TAG_KEY_TYPE	 0x44
#define ELE_KEY_IMPORT_TAG_KEY_SEC_SIZE	 0x45
#define ELE_KEY_IMPORT_TAG_KEY_LIFETIME	 0x46
#define ELE_KEY_IMPORT_TAG_KEY_LIFECYCLE 0x47
#define ELE_KEY_IMPORT_TAG_OEM_MK_ID	 0x50
#define ELE_KEY_IMPORT_TAG_WRAP_ALGO	 0x51
#define ELE_KEY_IMPORT_TAG_WRAP_IV	 0x52
#define ELE_KEY_IMPORT_TAG_SIGN_ALGO	 0x54
#define ELE_KEY_IMPORT_TAG_WRAP_DATA	 0x55
#define ELE_KEY_IMPORT_TAG_SIGN		 0x5E

#define ELE_WRAP_AES_CBC 2

/* ASN1 Long format length encoding tag */
#define ASN1_LONG_LENGTH BIT(7)

/**
 * tlv_convert_numeral() - Convert buffer to numeral
 * @numeral: Numeral value converted
 * @buffer: Buffer to convert
 * @buffer_len: length of the @buffer
 *
 * Return
 * PASSED     - Success
 * -FAILED    - Failure
 * -BAD_ARGS  - Invalid Argument
 */
static int tlv_convert_numeral(uint64_t *numeral, uint8_t *buffer,
			       size_t buffer_len)
{
	size_t i = 0;

	if (!buffer_len) {
		*numeral = 0;
		return ERR_CODE(PASSED);
	}

	if (!buffer && buffer_len)
		return ERR_CODE(BAD_ARGS);

	*numeral = 0;

	if (buffer_len > sizeof(*numeral)) {
		DBG_PRINT("TLV numeral decoding error\n");
		return ERR_CODE(FAILED);
	}

	for (; i < buffer_len; i++)
		*numeral |= (uint64_t)buffer[i] << ((buffer_len - 1 - i) * 8);

	return ERR_CODE(PASSED);
}

/**
 * encode_asn1_length() - Encode a length in ASN1 length format
 * @len: [in] Length to encode
 * @out: [out] Resulting encoding. Output the incremented pointer
 * @outlen: [in/out] Length of the result
 *
 * If the @out is NULL, function calculates the output buffer length and
 * returns PASSED.
 *
 * return:
 * PASSED     - Success
 * -FAILED    - Failure
 * -BAD_ARGS  - Invalid Argument
 */
static int encode_asn1_length(size_t len, uint8_t **out, size_t *outlen)
{
	size_t x = len;
	size_t nb_octets = 1;
	uint8_t *p = NULL;

	if (!out)
		return ERR_CODE(BAD_ARGS);

	if (x > ASN1_LONG_LENGTH - 1) {
		while (x != 0) {
			if (INC_OVERFLOW(nb_octets, 1))
				return ERR_CODE(FAILED);

			x >>= 8;
		}
	}

	if (nb_octets > sizeof(*outlen))
		return ERR_CODE(BAD_ARGS);

	if (!*out) {
		*outlen = nb_octets;
		return ERR_CODE(PASSED);
	}

	if (*outlen < nb_octets)
		return ERR_CODE(BAD_ARGS);

	p = *out;
	if (!p)
		return ERR_CODE(BAD_ARGS);

	*outlen = nb_octets;

	nb_octets--;
	if (!nb_octets) {
		*p++ = len & UINT8_MAX;
	} else {
		*p++ = (ASN1_LONG_LENGTH | nb_octets) & UINT8_MAX;

		while (nb_octets--)
			*p++ = (len >> (8 * nb_octets)) & UINT8_MAX;
	}

	*out = p;

	return ERR_CODE(PASSED);
}

static void free_tlv(struct tlv *tlv, size_t nb_tlv)
{
	size_t i = 0;

	for (; i < nb_tlv; i++) {
		if (tlv[i].new_buf && tlv[i].buf)
			free(tlv[i].buf);
	}
}

static int allocate_fill_blob(struct tbuffer *blob, struct tlv *tlv,
			      size_t nb_tlv)
{
	int res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	uint8_t *buf = NULL;
	uint8_t *p = NULL;
	size_t acc_len = 0;
	size_t buf_len = 0;
	size_t len = 0;
	size_t i = 0;
	size_t j = 0;

	buf_len = blob->length;

	if (buf_len) {
		buf = calloc(1, buf_len);
		if (!buf)
			goto end;
	}

	p = buf;
	for (i = 0; i < nb_tlv; i++) {
		acc_len += sizeof(tlv[i].tag);

		if (p) {
			if (acc_len >= buf_len) {
				res = ERR_CODE(FAILED);
				goto end;
			}

			memcpy(p, &tlv[i].tag, sizeof(tlv[i].tag));
			p += sizeof(tlv[i].tag);

			len = buf_len - acc_len;
		}

		res = encode_asn1_length(tlv[i].length, &p, &len);
		if (res != ERR_CODE(PASSED))
			goto end;

		if (INC_OVERFLOW(acc_len, len)) {
			res = ERR_CODE(FAILED);
			goto end;
		}

		if (p && acc_len >= buf_len) {
			res = ERR_CODE(FAILED);
			goto end;
		}

		if (INC_OVERFLOW(acc_len, tlv[i].length)) {
			res = ERR_CODE(FAILED);
			goto end;
		}

		if (!p)
			continue;

		if (acc_len > buf_len) {
			res = ERR_CODE(FAILED);
			goto end;
		}

		switch (tlv[i].val_type) {
		case t_buffer_hex:
			if (tlv[i].buf)
				memcpy(p, tlv[i].buf, tlv[i].length);

			break;

		case t_uint:
			for (j = 0; j < tlv[i].length; j++)
				p[j] = (tlv[i].numeral >>
					((tlv[i].length - 1 - j) * 8)) &
				       UCHAR_MAX;
			break;

		default:
			res = ERR_CODE(FAILED);
			goto end;
		}

		p += tlv[i].length;
	}

	blob->length = acc_len;

	res = ERR_CODE(PASSED);

end:
	if (res != ERR_CODE(PASSED) && buf)
		free(buf);
	else
		blob->data = buf;

	return res;
}

int util_tlv_encode_ele_import_tlv(struct subtest_data *subtest,
				   struct tbuffer *blob,
				   struct tbuffer *wrap_key,
				   unsigned int oem_mk_id, size_t sign_length)
{
	int res = ERR_CODE(BAD_ARGS);

	struct json_object *oargs = NULL;
	struct tbuffer buf = { 0 };
	struct tlv tlv[14] = { 0 };

	if (!subtest || !blob || !wrap_key)
		return res;

	if (blob->data)
		free(blob->data);

	blob->data = NULL;
	blob->length = 0;

	res = util_read_json_type(&oargs, OP_ARGS_OBJ, t_object,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Tag Magic */
	tlv[0].tag = ELE_KEY_IMPORT_TAG_MAGIC;
	tlv[0].val_type = t_buffer_hex;
	tlv[0].new_buf = false;
	tlv[0].length = sizeof(ELE_KEY_IMPORT_VAL_MAGIC);
	tlv[0].buf = (uint8_t *)ELE_KEY_IMPORT_VAL_MAGIC;

	/* Tag key identifier */
	tlv[1].tag = ELE_KEY_IMPORT_TAG_KEY_ID;

	res = util_read_json_type(&buf, ID_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Missing key identifier");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	tlv[1].val_type = t_uint;
	tlv[1].new_buf = false;
	tlv[1].length = 4;

	if (res == ERR_CODE(PASSED)) {
		res = tlv_convert_numeral(&tlv[1].numeral, buf.data,
					  buf.length);
		if (buf.data)
			free(buf.data);

		if (res != ERR_CODE(PASSED))
			goto end;
	}

	/* Tag key permitted algorithm */
	tlv[2].tag = ELE_KEY_IMPORT_TAG_KEY_ALGO;
	res = util_read_json_type(&buf, PERMITTED_ALGO_OBJ, t_buffer_hex,
				  oargs);
	if (res != ERR_CODE(PASSED) || !buf.data || buf.length != 4) {
		DBG_PRINT("Missing or incorrect key permitted algorithm");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	tlv[2].val_type = t_buffer_hex;
	tlv[2].new_buf = true;
	tlv[2].length = buf.length;
	tlv[2].buf = buf.data;

	/* Tag key usage */
	tlv[3].tag = ELE_KEY_IMPORT_TAG_KEY_USAGE;
	res = util_read_json_type(&buf, USAGE_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) || !buf.data || buf.length != 4) {
		DBG_PRINT("Missing or incorrect key usage");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	tlv[3].val_type = t_buffer_hex;
	tlv[3].new_buf = true;
	tlv[3].length = buf.length;
	tlv[3].buf = buf.data;

	/* Tag key type */
	tlv[4].tag = ELE_KEY_IMPORT_TAG_KEY_TYPE;
	res = util_read_json_type(&buf, TYPE_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) || !buf.data || buf.length != 2) {
		DBG_PRINT("Missing or incorrect key usage");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	tlv[4].val_type = t_buffer_hex;
	tlv[4].new_buf = true;
	tlv[4].length = buf.length;
	tlv[4].buf = buf.data;

	/* Tag key security size */
	tlv[5].tag = ELE_KEY_IMPORT_TAG_KEY_SEC_SIZE;
	tlv[5].val_type = t_uint;
	tlv[5].new_buf = false;
	tlv[5].length = 4;
	res = util_read_json_type(&tlv[5].numeral, SEC_SIZE_OBJ, t_uint, oargs);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Missing key security size");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	/* Tag key lifetime */
	tlv[6].tag = ELE_KEY_IMPORT_TAG_KEY_LIFETIME;
	res = util_read_json_type(&buf, LIFETIME_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) || !buf.data || buf.length != 4) {
		DBG_PRINT("Missing or incorrect key lifetime");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	tlv[6].val_type = t_buffer_hex;
	tlv[6].new_buf = true;
	tlv[6].length = buf.length;
	tlv[6].buf = buf.data;

	/* Tag key lifecycle */
	tlv[7].tag = ELE_KEY_IMPORT_TAG_KEY_LIFECYCLE;
	res = util_read_json_type(&buf, LIFECYCLE_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED) || !buf.data || buf.length != 4) {
		DBG_PRINT("Missing or incorrect key lifecycle");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	tlv[7].val_type = t_buffer_hex;
	tlv[7].new_buf = true;
	tlv[7].new_buf = true;
	tlv[7].length = buf.length;
	tlv[7].buf = buf.data;

	/* Tag OEM Master key identifier */
	tlv[8].tag = ELE_KEY_IMPORT_TAG_OEM_MK_ID;
	tlv[8].val_type = t_uint;
	tlv[8].new_buf = false;
	tlv[8].length = 4;
	tlv[8].numeral = oem_mk_id;

	/* Tag Wrapping algorithm */
	tlv[9].tag = ELE_KEY_IMPORT_TAG_WRAP_ALGO;
	tlv[9].val_type = t_uint;
	tlv[9].new_buf = false;
	tlv[9].length = 4;
	tlv[9].numeral = ELE_WRAP_AES_CBC;

	/* Tag Wrapping IV */
	tlv[10].tag = ELE_KEY_IMPORT_TAG_WRAP_IV;
	res = util_read_json_type(&buf, IV_OBJ, t_buffer_hex, oargs);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Missing wrapping IV");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	};

	tlv[10].val_type = t_buffer_hex;
	tlv[10].new_buf = true;
	tlv[10].length = buf.length;
	tlv[10].buf = buf.data;

	/* Tag Signing algorithm */
	tlv[11].tag = ELE_KEY_IMPORT_TAG_SIGN_ALGO;
	tlv[11].new_buf = false;
	tlv[11].val_type = t_uint;
	tlv[11].length = 4;
	tlv[11].numeral = 1;

	/* Tag Wrapped key data  */
	tlv[12].tag = ELE_KEY_IMPORT_TAG_WRAP_DATA;
	tlv[12].val_type = t_buffer_hex;
	tlv[12].new_buf = false;
	tlv[12].length = wrap_key->length;
	tlv[12].buf = wrap_key->data;

	/* Tag Signature  */
	tlv[13].tag = ELE_KEY_IMPORT_TAG_SIGN;
	tlv[13].val_type = t_buffer_hex;
	tlv[13].new_buf = false;
	tlv[13].length = sign_length;
	tlv[13].buf = NULL;

	/* First call to calculate the length of the blob */
	res = allocate_fill_blob(blob, tlv, ARRAY_SIZE(tlv));
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Second call to allocate and fill the blob */
	res = allocate_fill_blob(blob, tlv, ARRAY_SIZE(tlv));

	DBG_DHEX("ELE Import key blob", blob->data, blob->length);

end:
	free_tlv(tlv, ARRAY_SIZE(tlv));

	return res;
}
