/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __TAG_H__
#define __TAG_H__

/* Specified separators */
extern const char open_square_bracket;
extern const char close_square_bracket;
extern const char semicolon;
extern const char equal;
extern const char colon;

/* Whitespaces */
extern const char space;
extern const char carriage_return;
extern const char new_line;
extern const char tab;

/* Sections tags */
extern const char *subsystem_tag;
extern const char *operation_tag;

/* Parameters tags */
extern const char *version_tag;
extern const char *default_tag;
extern const char *key_type_values;
extern const char *key_size_range;
extern const char *hash_algo_values;
extern const char *hmac_algo_values;
extern const char *rng_range;
extern const char *sign_type_values;
extern const char *op_type_values;
extern const char *mode_values;

#endif /* __TAG_H__ */
