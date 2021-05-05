/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#define SMW_CONFIG_MAX_STRING_LENGTH 256

#define SMW_CONFIG_MAX_OPERATION_NAME_LENGTH 17

#define SMW_CONFIG_MAX_SUBSYSTEM_NAME_LENGTH 8

#define SMW_CONFIG_MAX_LOAD_METHOD_NAME_LENGTH 32

#define SMW_CONFIG_MAX_PARAMS_NAME_LENGTH 16

#define DEFINE_CONFIG_OPERATION_FUNC(operation)                                \
	struct operation_func operation##_func = {                             \
		.read = operation##_read_params,                               \
		.destroy = NULL,                                               \
		.print = operation##_print_params,                             \
		.check_subsystem_caps = operation##_check_subsystem_caps       \
	};                                                                     \
	struct operation_func *smw_##operation##_get_func(void)                \
	{                                                                      \
		return &operation##_func;                                      \
	}

struct ctx {
	void *mutex;
	unsigned int load_count;
};

enum load_method_id {
	/* Load / unload methods */
	LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD,
	LOAD_METHOD_ID_AT_FIRST_CALL_LOAD,
	LOAD_METHOD_ID_AT_CONTEXT_CREATION_DESTRUCTION,
	LOAD_METHOD_ID_NB,
	LOAD_METHOD_ID_INVALID
};

struct key_operation_params {
	enum operation_id operation_id;
	unsigned long key_type_bitmap;
	unsigned int key_size_min;
	unsigned int key_size_max;
};

struct hash_params {
	enum operation_id operation_id;
	unsigned long algo_bitmap;
};

struct hmac_params {
	enum operation_id operation_id;
	unsigned long algo_bitmap;
	unsigned long key_type_bitmap;
	unsigned int key_size_min;
	unsigned int key_size_max;
};

struct sign_verify_params {
	enum operation_id operation_id;
	unsigned long algo_bitmap;
	unsigned long key_type_bitmap;
	unsigned int key_size_min;
	unsigned int key_size_max;
	unsigned long sign_type_bitmap;
};

struct rng_params {
	enum operation_id operation_id;
	unsigned int length_min;
	unsigned int length_max;
};

struct cipher_params {
	enum operation_id operation_id;
	unsigned long mode_bitmap;
	unsigned long key_type_bitmap;
	unsigned long op_bitmap;
};

extern struct ctx ctx;

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
 * @min: Pointer where the minimum value is written.
 * @max: Pointer where the maximum value is written.
 *
 * This function reads the minimum and maximum values.
 * The pointer to the current char is moved to the next char
 * after the semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int read_range(char **start, char *end, unsigned int *min, unsigned int *max);

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
 *
 * This function parses a plaintext configuration and
 * fills the Configuration database.
 *
 * Return:
 * error code.
 */
int parse(char *buffer, unsigned int size);

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
 * set_subsystem_configured() - Set a Secure subsystem as configured.
 * @id: Secure Subsystem ID.
 *
 * This function sets a Secure subsystem as configured.
 *
 * Return:
 * none.
 */
void set_subsystem_configured(enum subsystem_id id);

/**
 * set_subsystem_load_method() - Set a Secure subsystem load method.
 * @id: Secure Subsystem ID.
 * @load_method_id: Load method ID.
 *
 * This function sets a Secure subsystem load method.
 *
 * Return:
 * none.
 */
void set_subsystem_load_method(enum subsystem_id id,
			       enum load_method_id load_method_id);

/**
 * set_subsystem_operation_bitmap() - Set a Secure subsystem operation bitmap.
 * @subsystem_id: Secure Subsystem ID.
 * @operation_id: Security Operation ID.
 *
 * This function sets a Secure subsystem operation bitmap.
 * The operation bitmap tells what Security Operations are configured for
 * the Secure Subsystem.
 *
 * Return:
 * none.
 */
void set_subsystem_operation_bitmap(enum subsystem_id subsystem_id,
				    enum operation_id operation_id);

/**
 * set_subsystem_default() - Set the default Secure Subsystem.
 * @subsystem_id: Secure Subsystem ID.
 * @operation_id: Security Operation ID.
 * @is_default: If true, the Secure Subsystem is the default subsystem.
 *
 * This function sets the default Secure Subsystem for a Security Operation.
 * If is_default is false, the Secure Subsystem is the default subsystem
 * if none has been set before.
 *
 * Return:
 * none.
 */
void set_subsystem_default(enum operation_id operation_id,
			   enum subsystem_id subsystem_id, bool is_default);

/**
 * store_operation_params() - Store the Security Operation configuration.
 * @operation_id: Security Operation ID.
 * @params: Pointer to the structure that contains the parameters.
 * @func: Pointer to the structure that contains the functions to manage
 *        the parameters.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function stores the Security Operation configuration for a given
 * a Secure Subsystem.
 *
 * Return:
 * none.
 */
int store_operation_params(enum operation_id operation_id, void *params,
			   struct operation_func *func,
			   enum subsystem_id subsystem_id);

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
 * print_key_params() - Print the Key Security Operations configuration.
 *
 * This function prints the Key Security Operations configuration.
 *
 * Return:
 * none.
 */
void print_key_params(void *params);

/**
 * print_hash_params() - Print the Hash configuration.
 *
 * This function prints the Hash configuration.
 *
 * Return:
 * none.
 */
void print_hash_params(void *params);

/**
 * print_sign_verify_params() - Print the Sign and Verify configuration.
 *
 * This function prints the Sign and Verify configuration.
 *
 * Return:
 * none.
 */
void print_sign_verify_params(void *params);

/**
 * check_security_size() - Check if the Security size if configured.
 * @security_size: .
 * @key_size_min: .
 * @key_size_max: .
 *
 * This function checks if the Security size if configured.
 *
 * Return:
 * * true:	- the Security size is within the range.
 * * false:	- the Security size is outside the range.
 */
bool check_security_size(unsigned int security_size, unsigned int key_size_min,
			 unsigned int key_size_max);

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
 * load_subsystems() - Load all configured Secure Subsystems.
 *
 * This function loads all configured Secure Subsystems.
 *
 * Return:
 * error code.
 */
void load_subsystems(void);

/**
 * load_subsystems() - Unload all configured Secure Subsystems.
 *
 * This function unloads all configured Secure Subsystems.
 *
 * Return:
 * error code.
 */
void unload_subsystems(void);
