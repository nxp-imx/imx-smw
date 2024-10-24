/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __SHA_H__
#define __SHA_H__

#define SHA_Ch(x, y, z)	    (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)    (((x) & ((y) | (z))) | ((y) & (z)))
#define SHA_Parity(x, y, z) ((x) ^ (y) ^ (z))

#define SHA1_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))

#define SHA256_SHR(bits, word)	((word) >> (bits))
#define SHA256_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))
#define SHA256_ROTR(bits, word) (((word) >> (bits)) | ((word) << (32 - (bits))))

#define SHA256_SIGMA0(word)                                                    \
	(SHA256_ROTR(2, word) ^ SHA256_ROTR(13, word) ^ SHA256_ROTR(22, word))
#define SHA256_SIGMA1(word)                                                    \
	(SHA256_ROTR(6, word) ^ SHA256_ROTR(11, word) ^ SHA256_ROTR(25, word))
#define SHA256_sigma0(word)                                                    \
	(SHA256_ROTR(7, word) ^ SHA256_ROTR(18, word) ^ SHA256_SHR(3, word))
#define SHA256_sigma1(word)                                                    \
	(SHA256_ROTR(17, word) ^ SHA256_ROTR(19, word) ^ SHA256_SHR(10, word))

#define SHA512_SHR(bits, word, ret)                                            \
	((ret)[0] =                                                            \
		 (((bits) < 32) && ((bits) >= 0)) ? ((word)[0] >> (bits)) : 0, \
	 (ret)[1] = ((bits) > 32)  ? ((word)[0] >> ((bits)-32)) :              \
		    ((bits) == 32) ? (word)[0] :                               \
		    ((bits) >= 0)  ? (((word)[0] << (32 - (bits))) |           \
				      ((word)[1] >> (bits))) :                 \
				     0)

#define SHA512_SHL(bits, word, ret)                                            \
	((ret)[0] = ((bits) > 32)  ? ((word)[1] << ((bits)-32)) :              \
		    ((bits) == 32) ? (word)[1] :                               \
		    ((bits) >= 0)  ? (((word)[0] << (bits)) |                  \
				      ((word)[1] >> (32 - (bits)))) :          \
				     0,                                         \
	 (ret)[1] =                                                            \
		 (((bits) < 32) && ((bits) >= 0)) ? ((word)[1] << (bits)) : 0)

#define SHA512_OR(word1, word2, ret)                                           \
	((ret)[0] = (word1)[0] | (word2)[0], (ret)[1] = (word1)[1] | (word2)[1])

#define SHA512_XOR(word1, word2, ret)                                          \
	((ret)[0] = (word1)[0] ^ (word2)[0], (ret)[1] = (word1)[1] ^ (word2)[1])

#define SHA512_ADD(word1, word2, ret)                                          \
	((ret)[1] = (word1)[1], (ret)[1] += (word2)[1],                        \
	 (ret)[0] = (word1)[0] + (word2)[0] + ((ret)[1] < (word1)[1]))

static uint32_t ADDTO2_temp;
#define SHA512_ADDTO2(word1, word2)                                            \
	(ADDTO2_temp = (word1)[1], (word1)[1] += (word2)[1],                   \
	 (word1)[0] += (word2)[0] + ((word1)[1] < ADDTO2_temp))

static uint32_t ROTR_temp1[2], ROTR_temp2[2];
#define SHA512_ROTR(bits, word, ret)                                           \
	(SHA512_SHR((bits), (word), ROTR_temp1),                               \
	 SHA512_SHL(64 - (bits), (word), ROTR_temp2),                          \
	 SHA512_OR(ROTR_temp1, ROTR_temp2, (ret)))

static uint32_t SIGMA0_temp1[2], SIGMA0_temp2[2], SIGMA0_temp3[2],
	SIGMA0_temp4[2];
#define SHA512_SIGMA0(word, ret)                                               \
	(SHA512_ROTR(28, (word), SIGMA0_temp1),                                \
	 SHA512_ROTR(34, (word), SIGMA0_temp2),                                \
	 SHA512_ROTR(39, (word), SIGMA0_temp3),                                \
	 SHA512_XOR(SIGMA0_temp2, SIGMA0_temp3, SIGMA0_temp4),                 \
	 SHA512_XOR(SIGMA0_temp1, SIGMA0_temp4, (ret)))

static uint32_t SIGMA1_temp1[2], SIGMA1_temp2[2], SIGMA1_temp3[2],
	SIGMA1_temp4[2];
#define SHA512_SIGMA1(word, ret)                                               \
	(SHA512_ROTR(14, (word), SIGMA1_temp1),                                \
	 SHA512_ROTR(18, (word), SIGMA1_temp2),                                \
	 SHA512_ROTR(41, (word), SIGMA1_temp3),                                \
	 SHA512_XOR(SIGMA1_temp2, SIGMA1_temp3, SIGMA1_temp4),                 \
	 SHA512_XOR(SIGMA1_temp1, SIGMA1_temp4, (ret)))

static uint32_t sigma0_temp1[2], sigma0_temp2[2], sigma0_temp3[2],
	sigma0_temp4[2];
#define SHA512_sigma0(word, ret)                                               \
	(SHA512_ROTR(1, (word), sigma0_temp1),                                 \
	 SHA512_ROTR(8, (word), sigma0_temp2),                                 \
	 SHA512_SHR(7, (word), sigma0_temp3),                                  \
	 SHA512_XOR(sigma0_temp2, sigma0_temp3, sigma0_temp4),                 \
	 SHA512_XOR(sigma0_temp1, sigma0_temp4, (ret)))

static uint32_t sigma1_temp1[2], sigma1_temp2[2], sigma1_temp3[2],
	sigma1_temp4[2];
#define SHA512_sigma1(word, ret)                                               \
	(SHA512_ROTR(19, (word), sigma1_temp1),                                \
	 SHA512_ROTR(61, (word), sigma1_temp2),                                \
	 SHA512_SHR(6, (word), sigma1_temp3),                                  \
	 SHA512_XOR(sigma1_temp2, sigma1_temp3, sigma1_temp4),                 \
	 SHA512_XOR(sigma1_temp1, sigma1_temp4, (ret)))

#define SHA_Ch_64(x, y, z, ret)                                                \
	((ret)[0] = (((x)[0] & ((y)[0] ^ (z)[0])) ^ (z)[0]),                   \
	 (ret)[1] = (((x)[1] & ((y)[1] ^ (z)[1])) ^ (z)[1]))

#define SHA_Maj_64(x, y, z, ret)                                               \
	(ret[0] = (((x)[0] & ((y)[0] | (z)[0])) | ((y)[0] & (z)[0])),          \
	 ret[1] = (((x)[1] & ((y)[1] | (z)[1])) | ((y)[1] & (z)[1])))

#endif /* __SHA_H__ */
