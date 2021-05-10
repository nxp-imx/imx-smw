// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

/* Specified separators */
const char open_square_bracket = '[';
const char close_square_bracket = ']';
const char semicolon = ';';
const char equal = '=';
const char colon = ':';

/* Whitespaces */
const char space = ' ';
const char carriage_return = '\r';
const char new_line = '\n';
const char tab = '\t';

/* Sections tags */
const char *subsystem_tag = "[SECURE_SUBSYSTEM]";
const char *operation_tag = "[SECURITY_OPERATION]";

/* Parameters tags */
const char *version_tag = "VERSION";
const char *default_tag = "DEFAULT;";
const char *key_type_values = "KEY_TYPE_VALUES";
const char *key_size_range = "KEY_SIZE_RANGE";
const char *hash_algo_values = "HASH_ALGO_VALUES";
const char *hmac_algo_values = "HMAC_ALGO_VALUES";
const char *rng_range = "RNG_RANGE";
const char *sign_type_values = "SIGN_TYPE_VALUES";
