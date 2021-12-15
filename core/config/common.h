/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#include "config.h"
#include "keymgr.h"

#define SMW_CONFIG_MAX_STRING_LENGTH 256

#define SMW_CONFIG_MAX_OPERATION_NAME_LENGTH 17

#define SMW_CONFIG_MAX_SUBSYSTEM_NAME_LENGTH 8

#define SMW_CONFIG_MAX_LOAD_METHOD_NAME_LENGTH 32

/* All <ALGO>_SIZE_RANGE must be smaller than SMW_CONFIG_MAX_PARAMS_NAME_LENGTH */
#define SMW_CONFIG_MAX_PARAMS_NAME_LENGTH 32

#define DEFINE_CONFIG_OPERATION_FUNC(operation)                                \
	struct operation_func operation##_func = {                             \
		.read = operation##_read_params,                               \
		.merge = operation##_merge_params,                             \
		.print = operation##_print_params,                             \
		.check_subsystem_caps = operation##_check_subsystem_caps       \
	};                                                                     \
	struct operation_func *smw_##operation##_get_func(void)                \
	{                                                                      \
		return &operation##_func;                                      \
	}

struct ctx {
	void *mutex;
	bool config_loaded;
};

struct psa_config {
	enum subsystem_id subsystem_id;
	bool alt;
};

enum load_method_id {
	/* Load / unload methods */
	LOAD_METHOD_ID_AT_FIRST_CALL_LOAD,
	LOAD_METHOD_ID_AT_CONTEXT_CREATION_DESTRUCTION,
	LOAD_METHOD_ID_NB,
	LOAD_METHOD_ID_INVALID
};

struct range {
	unsigned int min;
	unsigned int max;
};

struct op_key {
	unsigned long type_bitmap;
	struct range size_range[SMW_CONFIG_KEY_TYPE_ID_NB];
};

struct key_operation_params {
	unsigned long op_bitmap;
	struct op_key key;
};

struct hash_params {
	unsigned long algo_bitmap;
};

struct hmac_params {
	unsigned long algo_bitmap;
	struct op_key key;
};

struct sign_verify_params {
	unsigned long algo_bitmap;
	unsigned long sign_type_bitmap;
	struct op_key key;
};

struct rng_params {
	struct range range;
};

struct cipher_params {
	unsigned long mode_bitmap;
	unsigned long op_bitmap;
	struct op_key key;
};

extern struct ctx ctx;

/**
 * get_tag_prefix() - Get a tag prefix.
 * @tag: In/Out tag string.
 * @length: Length of the tag.
 * @suffix: Tag suffix to remove.
 *
 * This function checks if the suffix of @tag matches @suffix.
 * If true, the function sets the first char of @tag suffix
 * to null char. The caller can then use @tag as a null-terminated string
 * from which @suffix has been removed.
 * @suffix must be a null-terminated string.
 *
 * Return:
 * * true:      - the suffix is detected.
 * * false:     - the suffix is not detected.
 */
bool get_tag_prefix(char *tag, unsigned int length, const char *suffix);

/**
 * skip_insignificant_chars() - Skip insignificant chars.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 *
 * This function moves the read pointer to the next significant char.
 *
 * Return:
 * none.
 */
void skip_insignificant_chars(char **start, char *end);

/**
 * read_unsigned_integer() - Read an integer.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @dest: Pointer where the unsigned integer is written.
 *
 * This function reads an unsigned integer from the current char
 * of the buffer being parsed. The pointer to the current char is moved
 * to the next non-numerical char. Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int read_unsigned_integer(char **start, char *end, unsigned int *dest);

/**
 * read_range() - Read a range.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @range: Pointer to the range structure.
 *
 * This function reads the minimum and maximum values.
 * The pointer to the current char is moved to the next char
 * after the semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int read_range(char **start, char *end, struct range *range);

/**
 * read_key() - Read a Key configuration.
 * @tag: Tag string.
 * @length: Length of the tag.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @key_size_range_bitmap: Bitmap representing the Key size ranges already read.
 * @key: Key parameters.
 * @status: Error code set only if the tag is related to a key.
 *
 * This function reads a Key configuration from the current char
 * of the buffer being parsed until a semicolon is detected.
 * The pointer to the current char is moved to the next char
 * after the semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * * true:      - @tag is related to Key configuration.
 * * false:     - @tag is not related to Key configuration.
 */
bool read_key(char *tag, unsigned int length, char **start, char *end,
	      unsigned long *key_size_range_bitmap, struct op_key *key,
	      int *status);

/**
 * read_params_name() - Read parameters name.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @dest: Pointer where the unsigned integer is written.
 *
 * This function reads a string from the current char
 * of the buffer being parsed until a string delimiter is detected.
 * The pointer to the current char is moved to the next string delimiter,
 * or the next character after the character equal.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int read_params_name(char **start, char *end, char *dest);

/**
 * skip_param() - Skip a parameter.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 *
 * This function skips a parameter if its name is unknown.
 * The pointer to the current char is moved to the next char
 * after the next semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int skip_param(char **start, char *end);

/**
 * read_names() - Read a list of names.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @bitmap: Bitmap representing the configured names.
 * @array: Array associating an ID (index) to a name (value).
 * @size: Size of @array.
 *
 * This function reads a list of names from the current char
 * of the buffer being parsed until a semicolon is detected.
 * The pointer to the current char is moved to the next char
 * after the semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int read_names(char **start, char *end, unsigned long *bitmap,
	       const char *const array[], unsigned int size);

/**
 * read_key_type_names() - Read a list of Key types names.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @bitmap: Bitmap representing the configured names.
 *
 * This function reads a list of names from the current char
 * of the buffer being parsed until a semicolon is detected.
 * The pointer to the current char is moved to the next char
 * after the semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int read_key_type_names(char **start, char *end, unsigned long *bitmap);

/**
 * read_hash_algo_names() - Read a list of Hash algos names.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @bitmap: Bitmap representing the configured names.
 *
 * This function reads a list of names from the current char
 * of the buffer being parsed until a semicolon is detected.
 * The pointer to the current char is moved to the next char
 * after the semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int read_hash_algo_names(char **start, char *end, unsigned long *bitmap);

/**
 * parse() - Parse a plaintext configuration.
 * @buffer: Address of the first char of the plaintext configuration.
 * @size: Size of of rth plaintext configuration.
 * @offset: current offset in plaintext configuration.
 *
 * This function parses a plaintext configuration and
 * fills the Configuration database.
 *
 * Return:
 * error code.
 */
int parse(char *buffer, unsigned int size, unsigned int *offset);

/**
 * init_key_params() - Initialize the key parameters of a Security Operation.
 * @key: Key parameters.
 *
 * This function initializes the key parameters of a Security Operation.
 *
 * Return:
 * none.
 */
void init_key_params(struct op_key *key);

/**
 * init_database() - Initialize the Configuration database.
 * @reset: If true, dynamic memory is freed.
 *
 * This function initializes the Configuration database.
 *
 * Return:
 * none.
 */
void init_database(bool reset);

/**
 * set_psa_default_subsystem() - Set the PSA configuration.
 * @config: New PSA configuration.
 *
 * This function sets the PSA configuration.
 *
 * Return:
 * none.
 */
void set_psa_default_subsystem(struct psa_config *config);

/**
 * set_bit() - Set a bit in a bitmap.
 * @bitmap: Bitmap.
 * @size: Size of the bitmap in bits.
 * @offset: Offset of the bit to be set.
 *
 * This function sets a bit in a bitmap.
 *
 * Return:
 * none.
 */
void set_bit(unsigned long *bitmap, unsigned int size, unsigned int offset);

/**
 * set_subsystem_configured() - Set a Secure Subsystem as configured.
 * @id: Secure Subsystem ID.
 *
 * This function sets a Secure Subsystem as configured.
 *
 * Return:
 * none.
 */
void set_subsystem_configured(enum subsystem_id id);

/**
 * is_subsystem_configured() - Tell if a Secure Subsystem is configured.
 * @id: Secure Subsystem ID.
 *
 * This function tells if Secure Subsystem is configured.
 *
 * Return:
 * * true:	- the Secure Subsystem is configured.
 * * false:	- the Secure Subsystem is not configured.
 */
bool is_subsystem_configured(enum subsystem_id id);

/**
 * set_subsystem_load_method() - Set a Secure Subsystem load method.
 * @id: Secure Subsystem ID.
 * @load_method_id: Load method ID.
 *
 * This function sets a Secure Subsystem load method if not already set.
 *
 * Return:
 * error code.
 */
int set_subsystem_load_method(enum subsystem_id id,
			      enum load_method_id load_method_id);

/**
 * store_operation_params() - Store the Security Operation configuration.
 * @operation_id: Security Operation ID.
 * @params: Pointer to the structure that contains the parameters.
 * @func: Pointer to the structure that contains the functions to manage
 *        the parameters.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function stores the Security Operation configuration for a given
 * Secure Subsystem.
 *
 * Return:
 * error code.
 */
int store_operation_params(enum operation_id operation_id, void *params,
			   struct operation_func *func,
			   enum subsystem_id subsystem_id);

/**
 * get_operation_params() - Get an operation parameters.
 * @operation_id: Security Operation ID.
 * @subsystem_id: Secure Subsystem ID.
 * @params: Pointer to the data structure
 *          that describes the parameters.
 *
 * This function gets the parameters configured for
 * this Security Operation.
 *
 * Return:
 * error code.
 */
int get_operation_params(enum operation_id operation_id,
			 enum subsystem_id subsystem_id, void *params);

/**
 * get_operation_func() - Get the Security Operation functions.
 * @operation_id: Security Operation ID.
 *
 * This function gets a Security Operation functions.
 *
 * Return:
 * * pointer to the data structure containing the functions pointers
 *   associated with the Security Operation.
 */
struct operation_func *get_operation_func(enum operation_id id);

/**
 * print_key_params() - Print the Key parameters of a Security Operation.
 *
 * This function prints the Key parameters of a Security Operation.
 *
 * Return:
 * none.
 */
void print_key_params(struct op_key *key);

/**
 * print_database() - Print the Configuration database.
 *
 * This function prints the Configuration database.
 *
 * Return:
 * none.
 */
void print_database(void);

/**
 * get_load_method_id() - Get the load method ID associated to a name.
 * @name: Name as a string.
 * @id: Pointer where the load method ID is written.
 *
 * This function gets the load method ID associated to a name.
 *
 * Return:
 * error code.
 */
int get_load_method_id(const char *name, enum load_method_id *id);

/**
 * get_operation_id() - Get the Security Operation ID associated to a name.
 * @name: Name as a string.
 * @id: Pointer where the Security Operation ID is written.
 *
 * This function gets the Security Operation ID associated to a name.
 *
 * Return:
 * error code.
 */
int get_operation_id(const char *name, enum operation_id *id);

/**
 * merge_key_params() - Merge two operation keys parameters.
 * @key_caps: Current key capabilities.
 * @key_params: Key parameters to be merged.
 *
 * This function merges @key_params into @key_caps.
 *
 * Return:
 * none.
 */
void merge_key_params(struct op_key *key_caps, struct op_key *key_params);

/**
 * check_id() - Is an ID configured.
 * @id: Value ID.
 * @bitmap: Bitmap representing the configured values.
 *
 * This function states if a parameter value is configured
 * for a Security Operation. The configuration is stored as a bitmap.
 *
 * Return:
 * * true:	- parameter value is configured.
 * * false:	- parameter value is not configured.
 */
bool check_id(unsigned int id, unsigned long bitmap);

/**
 * check_size() - Is a size configured.
 * @size: Key size or random number size.
 * @range: Range configured.
 *
 * This function states if a size is configured for a Security Operation.
 *
 * Return:
 * * true:      - size is configured.
 * * false:     - size is not configured.
 */
bool check_size(unsigned int size, struct range *range);

/**
 * check_key() - Is a key configured.
 * @key_identifier: Key identifier.
 * @key_params: Key parameters.
 *
 * This function states if a key is configured for a Security Operation.
 *
 * Return:
 * * true:      - key is configured.
 * * false:     - key is not configured.
 */
bool check_key(struct smw_keymgr_identifier *key_identifier,
	       struct op_key *key_params);

/**
 * unload_subsystems() - Unload all configured Secure Subsystems.
 *
 * This function unloads all configured Secure Subsystems.
 *
 * Return:
 * error code.
 */
void unload_subsystems(void);

/**
 * is_psa_default_alt_enabled() - Tell if ENABLE_PSA_DEFAULT_ALT is enabled.
 *
 * This function tells if ENABLE_PSA_DEFAULT_ALT option is enabled.
 *
 * Return:
 * * true:  - ENABLE_PSA_DEFAULT_ALT is enabled.
 * * false: - ENABLE_PSA_DEFAULT_ALT is not enabled.
 */
bool is_psa_default_alt_enabled(void);
