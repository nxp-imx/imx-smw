// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <ctype.h>
#include <errno.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "builtin_macros.h"

#include "util.h"
#include "test_check.h"

#define IMX8ULP "imx8ulp"
#define IMX943	"imx943"
#define IMX95	"imx95"

#define TO_CK_BYTES(out, val)                                                  \
	({                                                                     \
		__typeof__(out) _out = (out);                                  \
		for (size_t i = 0; i < sizeof(val); i++)                       \
			_out[i] = GET_BYTE(val, i);                            \
	})

#define TO_INT(out, buf, len)                                                  \
	({                                                                     \
		__typeof__(out) _out = 0;                                      \
		__typeof__(buf) _buf = (buf);                                  \
		size_t i = len;                                                \
		int ret = 0;                                                   \
		if (i > sizeof(_out)) {                                        \
			ret = 1;                                               \
		} else {                                                       \
			_out = _buf[--i] & UINT8_MAX;                          \
			for (; i; i--) {                                       \
				_out <<= 8;                                    \
				_out |= _buf[i - 1] & UINT8_MAX;               \
			}                                                      \
			out = _out;                                            \
		}                                                              \
		ret;                                                           \
	})

/* Same as defined in osal/linux/config.c */
#define SMW_ETC_CNF "/etc/opt/smw/smw.conf"

#define SMW_CNF_TOKEN_COMMENT	    '#'
#define SMW_CNF_TOKEN_SECTION_START '['
#define SMW_CNF_TOKEN_SECTION_END   ']'
#define SMW_CNF_TOKEN_EQUAL	    '='
#define SMW_CNF_TOKEN_EOL	    '\n'

#define SMW_TOKEN_SETUP_NAME	    "setup"
#define SMW_TOKEN_DATABASE_NAME	    "database"
#define SMW_TOKEN_SETUP_NAME_LEN    (sizeof(SMW_TOKEN_SETUP_NAME) - 1)
#define SMW_TOKEN_DATABASE_NAME_LEN (sizeof(SMW_TOKEN_DATABASE_NAME) - 1)

#define SQL_CMD_DELETE_OBJECT "DELETE FROM OBJECTS WHERE \"0x1\" = %u;"

enum smw_cnf_state {
	SMW_CNF_STATE_NONE,
	SMW_CNF_STATE_COMMENT,
	SMW_CNF_STATE_SECTION,
	SMW_CNF_STATE_SECTION_NAME,
	SMW_CNF_STATE_DATABASE_ENTRY,
	SMW_CNF_STATE_UNUSED_ENTRY,
};

/**
 * string_to_lower() - Convert a string to lowercase
 * @src: String to convert
 * @length: Length of source string to convert
 */
static void string_to_lower(char *src, size_t length)
{
	for (size_t idx = 0; idx < strlen(src) && idx < length; idx++) {
		if (src[idx] >= 'A' && src[idx] <= 'Z')
			src[idx] += 'a' - 'A';
	}
}

static size_t byte_to_rfc2279_len(const CK_BYTE_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src; idx++, len++)
		if (src[idx] > 0x7F) {
			if (INC_OVERFLOW(len, 1))
				return 0;
		}

	return len;
}

static size_t byte_to_rfc2279(CK_UTF8CHAR_PTR dst, size_t len_dst,
			      const CK_BYTE_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src && len < len_dst; idx++, len++) {
		if (src[idx] > 0x7F) {
			if (len_dst <= len + 1)
				return idx;

			dst[len] = ((src[idx] >> 6) & 0x1F) | 0xC0;
			dst[++len] = (src[idx] & 0x3F) | 0x80;
		} else {
			dst[len] = src[idx];
		}
	}

	return idx;
}

static size_t rfc2279_to_byte_len(const CK_UTF8CHAR_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src; idx++) {
		if ((src[idx] & 0xE0) == 0xE0) {
			return 0;
		} else if ((src[idx] & 0xC0) == 0x80) {
			return 0;
		} else if ((src[idx] & 0xE0) == 0xC0) {
			if (len_src <= idx + 1)
				return 0;

			if ((src[++idx] & 0xC0) != 0x80)
				return 0;

			if (INC_OVERFLOW(len, 1))
				return 0;
		} else {
			if (INC_OVERFLOW(len, 1))
				return 0;
		}
	}

	return len;
}

static size_t rfc2279_to_byte(CK_BYTE_PTR dst, size_t len_dst,
			      const CK_UTF8CHAR_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src && len < len_dst; idx++, len++) {
		if ((src[idx] & 0xE0) == 0xE0) {
			return idx;
		} else if ((src[idx] & 0xC0) == 0x80) {
			return idx;
		} else if ((src[idx] & 0xE0) == 0xC0) {
			if (len_src <= idx + 1)
				return idx;

			if ((src[idx + 1] & 0xC0) != 0x80)
				return idx;

			dst[len] = src[idx] << 6;
			dst[len] |= src[++idx] & 0x3F;
		} else {
			dst[len] = src[idx];
		}
	}

	return idx;
}

bool util_compare_buffers(unsigned char *buffer, size_t buffer_len,
			  unsigned char *expected_buffer, size_t expected_len)
{
	bool status = false;

	if (buffer_len != expected_len)
		return status;

	if (buffer && expected_buffer &&
	    !memcmp(buffer, expected_buffer, buffer_len)) {
		status = true;
	}

	return status;
}

bool is_seco_subsystem(void)
{
#if SECO_TESTS_ENABLED
	return true;
#else
	return false;
#endif
}

bool is_ele_subsystem(void)
{
#if ELE_TESTS_ENABLED
	return true;
#else
	return false;
#endif
}

bool is_tee_subsystem(void)
{
#if TEE_TESTS_ENABLED
	return true;
#else
	return false;
#endif
}

static bool compare_hostname(const char *device)
{
	char hostname[256] = { 0 };

	if (gethostname(hostname, sizeof(hostname))) {
		TEST_OUT("%s (%d): Unable to get the hostname\n", __func__,
			 __LINE__);
		return false;
	}

	string_to_lower(hostname, strlen(hostname));

	TEST_OUT("%s (%d): hostname: %s, device name: %s\n", __func__, __LINE__,
		 hostname, device);

	if (!strncmp(hostname, device, strlen(device)))
		return true;

	return false;
}

static CK_RV util_get_database_path(char **database_path, char *smw_etc_cnf)
{
	int ret = CKR_ARGUMENTS_BAD;
	FILE *f = NULL;
	char token = 0;
	char section_name[80] = { 0 };
	unsigned int section_name_len = 0;
	char key_name[80] = { 0 };
	unsigned int key_name_len = 0;
	char value[80] = { 0 };
	unsigned int value_len = 0;
	unsigned int state = SMW_CNF_STATE_NONE;

	if (!database_path || !smw_etc_cnf)
		return ret;

	f = fopen(smw_etc_cnf, "r");
	if (!f)
		return CKR_GENERAL_ERROR;

	while (!feof(f)) {
		if (fscanf(f, "%c", &token) != 1)
			break;

		if (isblank(token))
			continue;

		switch (token) {
		case SMW_CNF_TOKEN_COMMENT:
			if (state == SMW_CNF_STATE_NONE ||
			    state == SMW_CNF_STATE_SECTION)
				state = SMW_CNF_STATE_COMMENT;
			break;

		case SMW_CNF_TOKEN_EOL:
			if (state == SMW_CNF_STATE_DATABASE_ENTRY) {
				*database_path = calloc(value_len + 1, 1);
				if (*database_path) {
					memcpy(*database_path, value,
					       value_len);
					ret = CKR_OK;
				} else {
					ret = CKR_HOST_MEMORY;
				}

				goto end;
			} else {
				if (section_name_len) {
					key_name_len = 0;
					state = SMW_CNF_STATE_SECTION;
				} else {
					state = SMW_CNF_STATE_NONE;
				}
			}
			break;

		case SMW_CNF_TOKEN_SECTION_START:
			if (state == SMW_CNF_STATE_NONE) {
				section_name_len = 0;
				state = SMW_CNF_STATE_SECTION_NAME;
			}
			break;

		case SMW_CNF_TOKEN_SECTION_END:
			if (state == SMW_CNF_STATE_SECTION_NAME)
				state = SMW_CNF_STATE_SECTION;
			break;

		case SMW_CNF_TOKEN_EQUAL:
			if (state == SMW_CNF_STATE_SECTION) {
				value_len = 0;
				state = SMW_CNF_STATE_UNUSED_ENTRY;
				if (section_name_len ==
					    SMW_TOKEN_SETUP_NAME_LEN &&
				    key_name_len ==
					    SMW_TOKEN_DATABASE_NAME_LEN &&
				    !strncmp(section_name, SMW_TOKEN_SETUP_NAME,
					     section_name_len) &&
				    !strncmp(key_name, SMW_TOKEN_DATABASE_NAME,
					     key_name_len))
					state = SMW_CNF_STATE_DATABASE_ENTRY;
			}
			break;

		default:
			switch (state) {
			case SMW_CNF_STATE_NONE:
			case SMW_CNF_STATE_COMMENT:
				break;

			case SMW_CNF_STATE_SECTION_NAME:
				section_name[section_name_len] = token;
				if (INC_OVERFLOW(section_name_len, 1)) {
					ret = CKR_ARGUMENTS_BAD;
					goto end;
				}
				break;

			case SMW_CNF_STATE_SECTION:
				key_name[key_name_len] = token;
				if (INC_OVERFLOW(key_name_len, 1)) {
					ret = CKR_ARGUMENTS_BAD;
					goto end;
				}
				break;

			default:
				value[value_len] = token;
				if (INC_OVERFLOW(value_len, 1)) {
					ret = CKR_ARGUMENTS_BAD;
					goto end;
				}
				break;
			}
			break;
		}
	}

end:
	if (fclose(f))
		perror("fclose()");

	return ret;
}

bool is_8ulp(void)
{
	return compare_hostname(IMX8ULP);
}

bool is_95(void)
{
	return compare_hostname(IMX95);
}

bool is_943(void)
{
	return compare_hostname(IMX943);
}

CK_RV util_set_unique_id(CK_UTF8CHAR_PTR unique_id, CK_ULONG_PTR length,
			 CK_OBJECT_CLASS class, unsigned int id)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	CK_BYTE_PTR buffer = NULL_PTR;
	CK_ULONG size = 0;
	CK_ULONG unique_id_length = 0;

	if (!length)
		return ret;

	size = sizeof(CK_OBJECT_CLASS) + sizeof(id);
	buffer = malloc(size);
	if (!buffer)
		return CKR_HOST_MEMORY;

	TO_CK_BYTES(&buffer[sizeof(CK_OBJECT_CLASS)], id);
	TO_CK_BYTES(buffer, class);

	/* Get RFC2279 length and allocate RFC2279 string */
	unique_id_length = byte_to_rfc2279_len(buffer, size);
	if (!unique_id_length) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (!unique_id || *length < unique_id_length) {
		ret = CKR_BUFFER_TOO_SMALL;
		*length = unique_id_length;
		goto end;
	}

	ret = CKR_FUNCTION_FAILED;
	if (byte_to_rfc2279(unique_id, unique_id_length, buffer, size) == size)
		ret = CKR_OK;

end:
	if (buffer)
		free(buffer);

	return ret;
}

CK_RV util_get_object_id(CK_UTF8CHAR_PTR unique_id, CK_ULONG length,
			 unsigned int *object_id)
{
	int ret = CKR_OK;

	CK_BYTE_PTR buffer = NULL_PTR;
	CK_ULONG size = 0;

	if (!length)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	size = rfc2279_to_byte_len(unique_id, length);
	if (!size)
		return CKR_FUNCTION_FAILED;

	buffer = malloc(size);
	if (!buffer)
		return CKR_HOST_MEMORY;

	if (rfc2279_to_byte(buffer, size, unique_id, length) != length) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (TO_INT(*object_id, &buffer[sizeof(CK_OBJECT_CLASS)],
		   sizeof(unsigned int)))
		ret = CKR_ATTRIBUTE_VALUE_INVALID;

end:
	if (buffer)
		free(buffer);

	return ret;
}

CK_RV util_erase_database_object(unsigned int object_id)
{
	int ret = CKR_OK;
	int res = 0;
	char *database_path = NULL;
	sqlite3 *db = NULL;
	char *messageError = NULL;
	char *sql_cmd = NULL;
	int sql_len = snprintf(NULL, 0, SQL_CMD_DELETE_OBJECT, object_id);

	if (sql_len < 0)
		return CKR_FUNCTION_FAILED;

	if (INC_OVERFLOW(sql_len, 1))
		return CKR_FUNCTION_FAILED;

	sql_cmd = malloc((size_t)sql_len);
	if (!sql_cmd)
		return CKR_HOST_MEMORY;

	ret = util_get_database_path(&database_path, SMW_ETC_CNF);
	if (ret == CKR_OK) {
		res = sqlite3_open_v2(database_path, &db, SQLITE_OPEN_READWRITE,
				      NULL);
		if (res == SQLITE_OK) {
			sprintf(sql_cmd, SQL_CMD_DELETE_OBJECT, object_id);

			res = sqlite3_exec(db, sql_cmd, 0, 0, &messageError);
			if (res != SQLITE_OK) {
				TEST_OUT("SQL Error: %s\n", messageError);
				sqlite3_free(messageError);
				ret = CKR_FUNCTION_FAILED;
			}

			res = sqlite3_close(db);
			if (res != SQLITE_OK)
				ret = CKR_FUNCTION_FAILED;
		} else {
			ret = CKR_FUNCTION_FAILED;
		}

		free(database_path);
	}

	free(sql_cmd);

	return ret;
}
