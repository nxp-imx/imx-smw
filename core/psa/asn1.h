/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __ASN1__H__
#define __ASN1__H__

struct asn1_integer {
	size_t length;
	uint8_t *value;
};

/**
 * asn1_encode_sequence_integer() - Encode ASN.1 sequence of integers.
 * @data: Buffer where the ASN.1 sequence is to be written.
 * @data_size: Size of the @data buffer in bytes.
 * @sequence: Table of integers to be encoded.
 * @size: Size of the @sequence table.
 *
 * This function encodes an ASN.1 sequence of integers.
 *
 * Return:
 * Number of bytes encoded.
 */
size_t asn1_encode_sequence_integer(uint8_t *data, size_t data_size,
				    struct asn1_integer sequence[],
				    size_t size);

/**
 * asn1_decode_sequence_integer() - Decode ASN.1 sequence of integers.
 * @data: Buffer where the ASN.1 sequence is encoded.
 * @data_length: Length of the @data buffer in bytes.
 * @sequence: Table of integers decoded.
 * @size: Size of the @sequence table.
 *
 * This function decodes an ASN.1 sequence of integers. @size is the expected number of integers.
 *
 * Return:
 * 0:	Success.
 * -1:	Error
 */
int asn1_decode_sequence_integer(const uint8_t *data, size_t data_length,
				 struct asn1_integer sequence[], size_t size);

#endif /* __ASN1__H__ */
