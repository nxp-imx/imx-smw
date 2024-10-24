// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "smw_status.h"

#include "config.h"
#include "debug.h"
#include "utils.h"
#include "hash.h"
#include "sha.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_CONFIG_HASH_ALGO_ID_OFFSET                                         \
	(SMW_HASH_ALGO_NAME_MD5 - SMW_CONFIG_HASH_ALGO_ID_MD5)

int smw_utils_get_hash_algo_id(smw_hash_algo_t name,
			       enum smw_config_hash_algo_id *id)
{
	int status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_HASH_ALGO_NAME_NONE) {
		*id = SMW_CONFIG_HASH_ALGO_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_HASH_ALGO_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_HASH_ALGO_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void update_SHA1(const uint8_t block[SMW_HASH_BLOCK_SIZE_SHA1],
			uint32_t intermediate[SMW_HASH_INTERMEDIATE_SIZE_SHA1])
{
	const uint32_t K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
				0xCA62C1D6 };

	int t = 0;
	uint32_t temp = 0;
	uint32_t W[80] = { 0 };
	uint32_t A = intermediate[0];
	uint32_t B = intermediate[1];
	uint32_t C = intermediate[2];
	uint32_t D = intermediate[3];
	uint32_t E = intermediate[4];

	for (; t < 16; t++) {
		W[t] = ((uint32_t)block[t * 4]) << 24;
		W[t] |= ((uint32_t)block[t * 4 + 1]) << 16;
		W[t] |= ((uint32_t)block[t * 4 + 2]) << 8;
		W[t] |= ((uint32_t)block[t * 4 + 3]);
	}

	for (t = 16; t < 80; t++)
		W[t] = SHA1_ROTL(1,
				 W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

	for (t = 0; t < 20; t++) {
		// coverity[cert_int30_c_violation]
		temp = SHA1_ROTL(5, A) + SHA_Ch(B, C, D) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++) {
		// coverity[cert_int30_c_violation]
		temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++) {
		// coverity[cert_int30_c_violation]
		temp = SHA1_ROTL(5, A) + SHA_Maj(B, C, D) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++) {
		// coverity[cert_int30_c_violation]
		temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	// coverity[cert_int30_c_violation]
	intermediate[0] += A;
	// coverity[cert_int30_c_violation]
	intermediate[1] += B;
	// coverity[cert_int30_c_violation]
	intermediate[2] += C;
	// coverity[cert_int30_c_violation]
	intermediate[3] += D;
	// coverity[cert_int30_c_violation]
	intermediate[4] += E;
}

static void
update_SHA256(const uint8_t block[SMW_HASH_BLOCK_SIZE_SHA256],
	      uint32_t intermediate[SMW_HASH_INTERMEDIATE_SIZE_SHA256])
{
	const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
		0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
		0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
		0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
		0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
		0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	int t = 0;
	int t4 = 0;
	uint32_t temp1 = 0;
	uint32_t temp2 = 0;
	uint32_t W[64] = { 0 };
	uint32_t A = intermediate[0];
	uint32_t B = intermediate[1];
	uint32_t C = intermediate[2];
	uint32_t D = intermediate[3];
	uint32_t E = intermediate[4];
	uint32_t F = intermediate[5];
	uint32_t G = intermediate[6];
	uint32_t H = intermediate[7];

	for (t = t4 = 0; t < 16; t++, t4 += 4)
		W[t] = (((uint32_t)block[t4]) << 24) |
		       (((uint32_t)block[t4 + 1]) << 16) |
		       (((uint32_t)block[t4 + 2]) << 8) |
		       (((uint32_t)block[t4 + 3]));

	for (t = 16; t < 64; t++)
		// coverity[cert_int30_c_violation]
		W[t] = SHA256_sigma1(W[t - 2]) + W[t - 7] +
		       SHA256_sigma0(W[t - 15]) + W[t - 16];

	for (t = 0; t < 64; t++) {
		// coverity[cert_int30_c_violation]
		temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
		// coverity[cert_int30_c_violation]
		temp2 = SHA256_SIGMA0(A) + SHA_Maj(A, B, C);
		H = G;
		G = F;
		F = E;
		// coverity[cert_int30_c_violation]
		E = D + temp1;
		D = C;
		C = B;
		B = A;
		// coverity[cert_int30_c_violation]
		A = temp1 + temp2;
	}

	// coverity[cert_int30_c_violation]
	intermediate[0] += A;
	// coverity[cert_int30_c_violation]
	intermediate[1] += B;
	// coverity[cert_int30_c_violation]
	intermediate[2] += C;
	// coverity[cert_int30_c_violation]
	intermediate[3] += D;
	// coverity[cert_int30_c_violation]
	intermediate[4] += E;
	// coverity[cert_int30_c_violation]
	intermediate[5] += F;
	// coverity[cert_int30_c_violation]
	intermediate[6] += G;
	// coverity[cert_int30_c_violation]
	intermediate[7] += H;
}

static void
update_SHA224(const uint8_t block[SMW_HASH_BLOCK_SIZE_SHA224],
	      uint32_t intermediate[SMW_HASH_INTERMEDIATE_SIZE_SHA224])
{
	update_SHA256(block, intermediate);
}

static void
update_SHA512(const uint8_t block[SMW_HASH_BLOCK_SIZE_SHA512],
	      uint32_t intermediate[SMW_HASH_INTERMEDIATE_SIZE_SHA512])
{
	const uint32_t K[80 * 2] = {
		0x428A2F98, 0xD728AE22, 0x71374491, 0x23EF65CD, 0xB5C0FBCF,
		0xEC4D3B2F, 0xE9B5DBA5, 0x8189DBBC, 0x3956C25B, 0xF348B538,
		0x59F111F1, 0xB605D019, 0x923F82A4, 0xAF194F9B, 0xAB1C5ED5,
		0xDA6D8118, 0xD807AA98, 0xA3030242, 0x12835B01, 0x45706FBE,
		0x243185BE, 0x4EE4B28C, 0x550C7DC3, 0xD5FFB4E2, 0x72BE5D74,
		0xF27B896F, 0x80DEB1FE, 0x3B1696B1, 0x9BDC06A7, 0x25C71235,
		0xC19BF174, 0xCF692694, 0xE49B69C1, 0x9EF14AD2, 0xEFBE4786,
		0x384F25E3, 0x0FC19DC6, 0x8B8CD5B5, 0x240CA1CC, 0x77AC9C65,
		0x2DE92C6F, 0x592B0275, 0x4A7484AA, 0x6EA6E483, 0x5CB0A9DC,
		0xBD41FBD4, 0x76F988DA, 0x831153B5, 0x983E5152, 0xEE66DFAB,
		0xA831C66D, 0x2DB43210, 0xB00327C8, 0x98FB213F, 0xBF597FC7,
		0xBEEF0EE4, 0xC6E00BF3, 0x3DA88FC2, 0xD5A79147, 0x930AA725,
		0x06CA6351, 0xE003826F, 0x14292967, 0x0A0E6E70, 0x27B70A85,
		0x46D22FFC, 0x2E1B2138, 0x5C26C926, 0x4D2C6DFC, 0x5AC42AED,
		0x53380D13, 0x9D95B3DF, 0x650A7354, 0x8BAF63DE, 0x766A0ABB,
		0x3C77B2A8, 0x81C2C92E, 0x47EDAEE6, 0x92722C85, 0x1482353B,
		0xA2BFE8A1, 0x4CF10364, 0xA81A664B, 0xBC423001, 0xC24B8B70,
		0xD0F89791, 0xC76C51A3, 0x0654BE30, 0xD192E819, 0xD6EF5218,
		0xD6990624, 0x5565A910, 0xF40E3585, 0x5771202A, 0x106AA070,
		0x32BBD1B8, 0x19A4C116, 0xB8D2D0C8, 0x1E376C08, 0x5141AB53,
		0x2748774C, 0xDF8EEB99, 0x34B0BCB5, 0xE19B48A8, 0x391C0CB3,
		0xC5C95A63, 0x4ED8AA4A, 0xE3418ACB, 0x5B9CCA4F, 0x7763E373,
		0x682E6FF3, 0xD6B2B8A3, 0x748F82EE, 0x5DEFB2FC, 0x78A5636F,
		0x43172F60, 0x84C87814, 0xA1F0AB72, 0x8CC70208, 0x1A6439EC,
		0x90BEFFFA, 0x23631E28, 0xA4506CEB, 0xDE82BDE9, 0xBEF9A3F7,
		0xB2C67915, 0xC67178F2, 0xE372532B, 0xCA273ECE, 0xEA26619C,
		0xD186B8C7, 0x21C0C207, 0xEADA7DD6, 0xCDE0EB1E, 0xF57D4F7F,
		0xEE6ED178, 0x06F067AA, 0x72176FBA, 0x0A637DC5, 0xA2C898A6,
		0x113F9804, 0xBEF90DAE, 0x1B710B35, 0x131C471B, 0x28DB77F5,
		0x23047D84, 0x32CAAB7B, 0x40C72493, 0x3C9EBE0A, 0x15C9BEBC,
		0x431D67C4, 0x9C100D4C, 0x4CC5D4BE, 0xCB3E42B6, 0x597F299C,
		0xFC657E2A, 0x5FCB6FAB, 0x3AD6FAEC, 0x6C44198C, 0x4A475817
	};

	int t = 0;
	int t2 = 0;
	int t8 = 0;
	uint32_t temp1[2] = { 0 };
	uint32_t temp2[2] = { 0 };
	uint32_t temp3[2] = { 0 };
	uint32_t temp4[2] = { 0 };
	uint32_t temp5[2] = { 0 };
	uint32_t W[2 * 80] = { 0 };
	uint32_t A[2] = { 0 };
	uint32_t B[2] = { 0 };
	uint32_t C[2] = { 0 };
	uint32_t D[2] = { 0 };
	uint32_t E[2] = { 0 };
	uint32_t F[2] = { 0 };
	uint32_t G[2] = { 0 };
	uint32_t H[2] = { 0 };

	for (; t < 16; t++, t8 += 8) {
		W[t2++] = ((((uint32_t)block[t8])) << 24) |
			  ((((uint32_t)block[t8 + 1])) << 16) |
			  ((((uint32_t)block[t8 + 2])) << 8) |
			  ((((uint32_t)block[t8 + 3])));
		W[t2++] = ((((uint32_t)block[t8 + 4])) << 24) |
			  ((((uint32_t)block[t8 + 5])) << 16) |
			  ((((uint32_t)block[t8 + 6])) << 8) |
			  ((((uint32_t)block[t8 + 7])));
	}

	for (t = 16; t < 80; t++, t2 += 2) {
		SHA512_sigma1(&W[t2 - 2 * 2], temp1);
		// coverity[cert_int30_c_violation]
		SHA512_ADD(temp1, &W[t2 - 7 * 2], temp2);
		SHA512_sigma0(&W[t2 - 15 * 2], temp1);
		// coverity[cert_int30_c_violation]
		SHA512_ADD(temp1, &W[t2 - 16 * 2], temp3);
		// coverity[cert_int30_c_violation]
		SHA512_ADD(temp2, temp3, &W[t2]);
	}

	A[0] = intermediate[0];
	A[1] = intermediate[1];
	B[0] = intermediate[2];
	B[1] = intermediate[3];
	C[0] = intermediate[4];
	C[1] = intermediate[5];
	D[0] = intermediate[6];
	D[1] = intermediate[7];
	E[0] = intermediate[8];
	E[1] = intermediate[9];
	F[0] = intermediate[10];
	F[1] = intermediate[11];
	G[0] = intermediate[12];
	G[1] = intermediate[13];
	H[0] = intermediate[14];
	H[1] = intermediate[15];

	for (t = t2 = 0; t < 80; t++, t2 += 2) {
		SHA512_SIGMA1(E, temp1);
		// coverity[cert_int30_c_violation]
		SHA512_ADD(H, temp1, temp2);
		SHA_Ch_64(E, F, G, temp3);
		// coverity[cert_int30_c_violation]
		SHA512_ADD(temp2, temp3, temp4);
		// coverity[cert_int30_c_violation]
		SHA512_ADD(&K[t2], &W[t2], temp5);
		SHA512_ADD(temp4, temp5, temp1);
		SHA512_SIGMA0(A, temp3);
		SHA_Maj_64(A, B, C, temp4);
		SHA512_ADD(temp3, temp4, temp2);
		H[0] = G[0];
		H[1] = G[1];
		G[0] = F[0];
		G[1] = F[1];
		F[0] = E[0];
		F[1] = E[1];
		// coverity[cert_int30_c_violation]
		SHA512_ADD(D, temp1, E);
		D[0] = C[0];
		D[1] = C[1];
		C[0] = B[0];
		C[1] = B[1];
		B[0] = A[0];
		B[1] = A[1];
		// coverity[cert_int30_c_violation]
		SHA512_ADD(temp1, temp2, A);
	}

	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[0], A);
	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[2], B);
	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[4], C);
	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[6], D);
	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[8], E);
	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[10], F);
	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[12], G);
	// coverity[cert_int30_c_violation]
	SHA512_ADDTO2(&intermediate[14], H);
}

static void
update_SHA384(const uint8_t block[SMW_HASH_BLOCK_SIZE_SHA384],
	      uint32_t intermediate[SMW_HASH_INTERMEDIATE_SIZE_SHA384])
{
	update_SHA512(block, intermediate);
}

static void final_SHA1(struct smw_hash_context *context)
{
	if (context->block_length >=
	    SMW_HASH_BLOCK_SIZE_SHA1 - SMW_HASH_PAD_LENGTH_SHA1) {
		context->block.sha1[context->block_length++] = 0x80;

		while (context->block_length < SMW_HASH_BLOCK_SIZE_SHA1)
			context->block.sha1[context->block_length++] = 0;

		update_SHA1(context->block.sha1, context->intermediate.sha1);
	} else {
		context->block.sha1[context->block_length++] = 0x80;
	}

	while (context->block_length < SMW_HASH_BLOCK_SIZE_SHA1 - 8)
		context->block.sha1[context->block_length++] = 0;

	context->block.sha1[56] =
		(uint8_t)(context->message_length >> 56 & 0xFF);
	context->block.sha1[57] =
		(uint8_t)(context->message_length >> 48 & 0xFF);
	context->block.sha1[58] =
		(uint8_t)(context->message_length >> 40 & 0xFF);
	context->block.sha1[59] =
		(uint8_t)(context->message_length >> 32 & 0xFF);
	context->block.sha1[60] =
		(uint8_t)(context->message_length >> 24 & 0xFF);
	context->block.sha1[61] =
		(uint8_t)(context->message_length >> 16 & 0xFF);
	context->block.sha1[62] =
		(uint8_t)(context->message_length >> 8 & 0xFF);
	context->block.sha1[63] = (uint8_t)(context->message_length & 0xFF);

	update_SHA1(context->block.sha1, context->intermediate.sha1);
}

static void final_SHA256(struct smw_hash_context *context)
{
	if (context->block_length >=
	    (SMW_HASH_BLOCK_SIZE_SHA256 - SMW_HASH_PAD_LENGTH_SHA256)) {
		context->block.sha256[context->block_length++] = 0x80;

		while (context->block_length < SMW_HASH_BLOCK_SIZE_SHA256)
			context->block.sha256[context->block_length++] = 0;

		update_SHA256(context->block.sha256,
			      context->intermediate.sha256);
	} else {
		context->block.sha256[context->block_length++] = 0x80;
	}

	while (context->block_length < (SMW_HASH_BLOCK_SIZE_SHA256 - 8))
		context->block.sha256[context->block_length++] = 0;

	context->block.sha256[56] =
		(uint8_t)(context->message_length >> 56 & 0xFF);
	context->block.sha256[57] =
		(uint8_t)(context->message_length >> 48 & 0xFF);
	context->block.sha256[58] =
		(uint8_t)(context->message_length >> 40 & 0xFF);
	context->block.sha256[59] =
		(uint8_t)(context->message_length >> 32 & 0xFF);
	context->block.sha256[60] =
		(uint8_t)(context->message_length >> 24 & 0xFF);
	context->block.sha256[61] =
		(uint8_t)(context->message_length >> 16 & 0xFF);
	context->block.sha256[62] =
		(uint8_t)(context->message_length >> 8 & 0xFF);
	context->block.sha256[63] = (uint8_t)(context->message_length & 0xFF);

	update_SHA256(context->block.sha256, context->intermediate.sha256);
}

static void final_SHA224(struct smw_hash_context *context)
{
	final_SHA256(context);
}

static void final_SHA512(struct smw_hash_context *context)
{
	if (context->block_length >=
	    (SMW_HASH_BLOCK_SIZE_SHA512 - SMW_HASH_PAD_LENGTH_SHA512)) {
		context->block.sha512[context->block_length++] = 0x80;

		while (context->block_length < SMW_HASH_BLOCK_SIZE_SHA512)
			context->block.sha512[context->block_length++] = 0;

		update_SHA512(context->block.sha512,
			      context->intermediate.sha512);
	} else {
		context->block.sha512[context->block_length++] = 0x80;
	}

	while (context->block_length < (SMW_HASH_BLOCK_SIZE_SHA512 - 8))
		context->block.sha512[context->block_length++] = 0;

	context->block.sha512[120] =
		(uint8_t)(context->message_length >> 56 & 0xFF);
	context->block.sha512[121] =
		(uint8_t)(context->message_length >> 48 & 0xFF);
	context->block.sha512[122] =
		(uint8_t)(context->message_length >> 40 & 0xFF);
	context->block.sha512[123] =
		(uint8_t)(context->message_length >> 32 & 0xFF);
	context->block.sha512[124] =
		(uint8_t)(context->message_length >> 24 & 0xFF);
	context->block.sha512[125] =
		(uint8_t)(context->message_length >> 16 & 0xFF);
	context->block.sha512[126] =
		(uint8_t)(context->message_length >> 8 & 0xFF);
	context->block.sha512[127] = (uint8_t)(context->message_length & 0xFF);

	update_SHA512(context->block.sha512, context->intermediate.sha512);
}

static void final_SHA384(struct smw_hash_context *context)
{
	final_SHA512(context);
}

static void result_SHA1(struct smw_hash_context *context,
			uint8_t digest[SMW_HASH_DIGEST_SIZE_SHA1])
{
	unsigned int i = 0;

	for (; i < SMW_HASH_DIGEST_SIZE_SHA1; i++)
		digest[i] = (uint8_t)(context->intermediate.sha1[i >> 2] >>
					      (8 * (3 - (i & 0x03))) &
				      0xFF);
}

static void result_SHA224(struct smw_hash_context *context,
			  uint8_t digest[SMW_HASH_DIGEST_SIZE_SHA224])
{
	unsigned int i = 0;

	for (; i < SMW_HASH_DIGEST_SIZE_SHA224; i++)
		digest[i] = (uint8_t)(context->intermediate.sha224[i >> 2] >>
					      (8 * (3 - (i & 0x03))) &
				      0xFF);
}

static void result_SHA256(struct smw_hash_context *context,
			  uint8_t digest[SMW_HASH_DIGEST_SIZE_SHA256])
{
	unsigned int i = 0;

	for (; i < SMW_HASH_DIGEST_SIZE_SHA256; i++)
		digest[i] = (uint8_t)(context->intermediate.sha256[i >> 2] >>
					      8 * (3 - (i & 0x03)) &
				      0xFF);
}

static void result_SHA384(struct smw_hash_context *context,
			  uint8_t digest[SMW_HASH_DIGEST_SIZE_SHA384])
{
	unsigned int i = 0;
	unsigned int j = 0;

	for (; i < SMW_HASH_DIGEST_SIZE_SHA384;) {
		digest[i++] =
			(uint8_t)(context->intermediate.sha384[j] >> 24 & 0xFF);
		digest[i++] =
			(uint8_t)(context->intermediate.sha384[j] >> 16 & 0xFF);
		digest[i++] =
			(uint8_t)(context->intermediate.sha384[j] >> 8 & 0xFF);
		digest[i++] =
			(uint8_t)(context->intermediate.sha384[j++] & 0xFF);
	}
}

static void result_SHA512(struct smw_hash_context *context,
			  uint8_t digest[SMW_HASH_DIGEST_SIZE_SHA512])
{
	unsigned int i = 0;
	unsigned int j = 0;

	for (; i < SMW_HASH_DIGEST_SIZE_SHA512;) {
		digest[i++] =
			(uint8_t)(context->intermediate.sha512[j] >> 24 & 0xFF);
		digest[i++] =
			(uint8_t)(context->intermediate.sha512[j] >> 16 & 0xFF);
		digest[i++] =
			(uint8_t)(context->intermediate.sha512[j] >> 8 & 0xFF);
		digest[i++] =
			(uint8_t)(context->intermediate.sha512[j++] & 0xFF);
	}
}

#define H0_DEF(_hash_id)                                                       \
	static uint32_t h0_##_hash_id[SMW_HASH_INTERMEDIATE_SIZE_##_hash_id]

H0_DEF(SHA1) = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

H0_DEF(SHA224) = { 0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
		   0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4 };

H0_DEF(SHA256) = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
		   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

H0_DEF(SHA384) = { 0xCBBB9D5D, 0xC1059ED8, 0x629A292A, 0x367CD507,
		   0x9159015A, 0x3070DD17, 0x152FECD8, 0xF70E5939,
		   0x67332667, 0xFFC00B31, 0x8EB44A87, 0x68581511,
		   0xDB0C2E0D, 0x64F98FA7, 0x47B5481D, 0xBEFA4FA4 };

H0_DEF(SHA512) = { 0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B,
		   0x3C6EF372, 0xFE94F82B, 0xA54FF53A, 0x5F1D36F1,
		   0x510E527F, 0xADE682D1, 0x9B05688C, 0x2B3E6C1F,
		   0x1F83D9AB, 0xFB41BD6B, 0x5BE0CD19, 0x137E2179 };

#define HASH_INFO(_hash_id)                                                    \
	{                                                                      \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_hash_id,                 \
		.h0 = h0_##_hash_id,                                           \
		.h0_size = SMW_HASH_INTERMEDIATE_SIZE_##_hash_id,              \
		.block_size = SMW_HASH_BLOCK_SIZE_##_hash_id,                  \
		.digest_size = SMW_HASH_DIGEST_SIZE_##_hash_id,                \
		.update = update_##_hash_id, .final = final_##_hash_id,        \
		.result = result_##_hash_id                                    \
	}

struct hash_info {
	enum smw_config_hash_algo_id hash_id;
	uint32_t *h0;
	unsigned int h0_size;
	unsigned int block_size;
	unsigned int digest_size;
	void (*update)(const uint8_t *block, uint32_t *intermediate);
	void (*final)(struct smw_hash_context *context);
	void (*result)(struct smw_hash_context *context, uint8_t *digest);

} hash_info[] = {
	HASH_INFO(SHA1),   HASH_INFO(SHA224), HASH_INFO(SHA256),
	HASH_INFO(SHA384), HASH_INFO(SHA512),
};

static struct hash_info *get_hash_info(enum smw_config_hash_algo_id hash_id)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(hash_info);

	for (; i < size; i++) {
		if (hash_info[i].hash_id == hash_id)
			return &hash_info[i];
	}

	return NULL;
}

int smw_utils_hash(enum smw_config_hash_algo_id hash_id, unsigned char *input,
		   unsigned int input_length, unsigned char *digest,
		   unsigned int *digest_length)
{
	int status = SMW_STATUS_OK;
	struct smw_hash_context context = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_hash_init(hash_id, &context);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_hash_update(&context, input, input_length);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_hash_final(&context, digest, digest_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_hash_init(enum smw_config_hash_algo_id hash_id,
			struct smw_hash_context *context)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct hash_info *info = get_hash_info(hash_id);
	size_t size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		goto end;

	context->hash_id = hash_id;

	if (MUL_OVERFLOW(info->h0_size, sizeof(uint32_t), &size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	SMW_UTILS_MEMCPY(&context->intermediate, info->h0, size);

	SMW_UTILS_MEMSET(&context->block, 0, sizeof(context->block));

	context->block_length = 0;
	context->message_length = 0;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_hash_update(struct smw_hash_context *context,
			  const uint8_t *input, unsigned int input_length)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int remaining_length = input_length;
	size_t length = 0;
	struct hash_info *info = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!context)
		goto end;

	if (!input || !input_length) {
		status = SMW_STATUS_OK;
		goto end;
	}

	info = get_hash_info(context->hash_id);
	if (!info) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	if (context->block_length > info->block_size)
		goto end;

	if (MUL_OVERFLOW(input_length, 8, &length))
		goto end;

	if (ADD_OVERFLOW(context->message_length, length,
			 &context->message_length))
		goto end;

	if (context->block_length) {
		if (SUB_OVERFLOW(info->block_size, context->block_length,
				 &length))
			goto end;

		if (length > input_length)
			length = input_length;

		SMW_UTILS_MEMCPY((uint8_t *)&context->block +
					 context->block_length,
				 input, length);

		if (SUB_OVERFLOW(remaining_length, length, &remaining_length))
			goto end;

		if (ADD_OVERFLOW(context->block_length, length,
				 &context->block_length))
			status = SMW_STATUS_INVALID_PARAM;

		input += length;

		if (context->block_length == info->block_size) {
			info->update((const uint8_t *)&context->block,
				     (uint32_t *)&context->intermediate);
			context->block_length = 0;
		}
	}

	while (remaining_length > info->block_size) {
		info->update(input, (uint32_t *)&context->intermediate);

		if (SUB_OVERFLOW(remaining_length, info->block_size,
				 &remaining_length))
			goto end;

		input += info->block_size;
	}

	if (remaining_length) {
		context->block_length = remaining_length;
		SMW_UTILS_MEMCPY(&context->block, input, remaining_length);
	}

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_hash_final(struct smw_hash_context *context, uint8_t *digest,
			 unsigned int *digest_length)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	struct hash_info *info = NULL;

	if (!context)
		goto end;

	info = get_hash_info(context->hash_id);
	if (!info) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	if (!digest) {
		status = SMW_STATUS_OK;
		goto end;
	}

	if (info->digest_size > *digest_length) {
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	info->final(context);
	info->result(context, digest);

	SMW_UTILS_MEMSET(&context->block, 0, sizeof(context->block));

	context->block_length = 0;

	status = SMW_STATUS_OK;

end:
	if (info)
		*digest_length = info->digest_size;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
