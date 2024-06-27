// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "local.h"

#define SMW_ETC_CNF "/etc/opt/smw/smw.conf"

/* Internal return code */
#define RET_NO_ERROR	0
#define RET_ERROR	-1
#define RET_END_OF_FILE 1
#define RET_NEW_SECTION 2

#define TAG_SPACE	  ' '
#define TAG_COMMENT_HASH  '#'
#define TAG_COMMENT_SLASH '/'
#define TAG_COMMENT_STAR  '*'
#define TAG_CR		  '\r'
#define TAG_LF		  '\n'
#define TAG_SECTION	  '['
#define TAG_CNF_DELIM	  '='
#define TEE_CNF_TA_UUID	  "ta_uuid"
#define SECO_CNF_ID	  "id"
#define SECO_CNF_NONCE	  "nonce"
#define SECO_CNF_REPLAY	  "replay"
#define ELE_CNF_ID	  "id"
#define ELE_CNF_NONCE	  "nonce"
#define SMW_CONFIG_FILE	  "smw_config_file"
#define SMW_DATABASE	  "database"

struct cnf_section_desc {
	const char *entry;
	void *value;
	size_t length;
	unsigned int flag;
	int (*conv)(void *dst, size_t length, char *value);
};

/**
 * trim_str_null() - Remove CR/LF characters and whitespaces from a string
 * @dst: [out] Destination string
 * @src: [in] Source string (null terminated)
 *
 * Return:
 * RET_NO_ERROR  - Success
 * RET_ERROR     - Failure
 */
static int trim_str_null(char **dst, char *src)
{
	int ret = RET_NO_ERROR;
	char *tmp = NULL;
	char *end = NULL;
	char *p = src;
	size_t length = 0;
	const char delm_cr[] = { TAG_CR, 0 };
	const char delm_lf[] = { TAG_LF, 0 };

	length = strlen(src);

	/* Remove starting spaces */
	while (length && *p == TAG_SPACE) {
		p++;
		length--;
	}

	/*
	 * First remove the CR/LF if any
	 */
	end = p + length;

	tmp = strstr(p, delm_cr);
	if (tmp)
		end = tmp;

	tmp = strstr(p, delm_lf);
	if (tmp && tmp < end)
		end = tmp;

	/* Remove end of line spaces */
	while (end > p && *end == TAG_SPACE)
		end--;

	if (SUB_OVERFLOW((intptr_t)end, (intptr_t)p, &length)) {
		ret = RET_ERROR;
		goto end;
	}

	/* NULL character */
	length++;

	*dst = malloc(length);
	if (!*dst) {
		DBG_PRINTF(ERROR, "%s (%d) memory allocation\n", __func__,
			   __LINE__);
		ret = RET_ERROR;
		goto end;
	}

	(*dst)[length - 1] = 0;

	(void)memcpy(*dst, p, length - 1);

end:
	return ret;
}

/**
 * str_to_ui() - Convert a string to unsigned int
 * @str: String to convert
 *
 * Return:
 * unsigned int value.
 */
static unsigned int str_to_ui(char *str)
{
	char *end = NULL;
	unsigned long value = 0;
	unsigned int ret = 0;

	value = strtoul(str, &end, 0);

	if (SET_OVERFLOW(value, ret))
		ret = 0;

	return ret;
}

/**
 * str_to_us() - Convert a string to unsigned short
 * @str: String to convert
 *
 * Return:
 * unsigned int value.
 */
static unsigned short str_to_us(char *str)
{
	unsigned short ret = 0;
	unsigned int value = 0;

	value = str_to_ui(str);

	if (SET_OVERFLOW(value, ret))
		ret = 0;

	return ret;
}

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

/**
 * value_to_str_alloc() - Allocate and copy value to destination
 * @dst: [out] Pointer to the destination buffer
 * @dst_length: [in] Length of dst (not used)
 * @value: [in] Value to copy to the destination
 *
 * Return:
 * RET_NO_ERROR  - Success
 * RET_ERROR     - Error
 */
static int value_to_str_alloc(void *dst, size_t dst_length __maybe_unused,
			      char *value)
{
	int ret = RET_NO_ERROR;
	char *p = NULL;
	char **out = NULL;
	size_t length = 0;

	if (!dst)
		return RET_ERROR;

	out = (char **)dst;

	if (*out) {
		free(*out);
		*out = NULL;
	}

	ret = trim_str_null(&p, value);
	if (!ret && p) {
		length = strlen(p);

		if (length) {
			*out = malloc(length + 1);

			if (*out) {
				(*out)[length] = 0;
				memcpy(*out, p, length);
				ret = RET_NO_ERROR;
			}
		}
	}

	if (p)
		free(p);

	return ret;
}

/**
 * value_to_str() - Copy value to destination
 * @dst: [out] Pointer to the destination buffer
 * @dst_length: [in] Length of @dst
 * @value: [in] Value to copy to the destination
 *
 * Return:
 * RET_NO_ERROR  - Success
 * RET_ERROR     - Error
 */
static int value_to_str(void *dst, size_t dst_length, char *value)
{
	int ret = RET_ERROR;
	char *p = NULL;
	size_t length = 0;

	if (!dst)
		return ret;

	ret = trim_str_null(&p, value);
	if (!ret) {
		length = strlen(p);

		if (length) {
			if (dst) {
				memcpy(dst, p, MIN(length, dst_length));
				ret = RET_NO_ERROR;
			}
		}
	}

	if (p)
		free(p);

	return ret;
}

/**
 * value_to_uint() - Convert the value to unsigned integer
 * @dst: [out] Pointer to the unsigned integer
 * @dst_length: [in] Length of dst (not used)
 * @value: [in] Value to convert to unsigned integer
 *
 * Return:
 * RET_NO_ERROR  - Success
 * RET_ERROR     - Error
 */
static int value_to_uint(void *dst, size_t dst_length __maybe_unused,
			 char *value)
{
	int ret = RET_ERROR;

	if (dst) {
		*((unsigned int *)dst) = str_to_ui(value);
		ret = RET_NO_ERROR;
	}

	return ret;
}

/**
 * value_to_uint() - Convert the value to unsigned short
 * @dst: [out] Pointer to the unsigned short
 * @dst_length: [in] Length of dst (not used)
 * @value: [in] Value to convert to unsigned short
 *
 * Return:
 * RET_NO_ERROR  - Success
 * RET_ERROR     - Error
 */
static int value_to_ushort(void *dst, size_t dst_length __maybe_unused,
			   char *value)
{
	int ret = RET_ERROR;

	if (dst) {
		*((unsigned short *)dst) = str_to_us(value);
		ret = RET_NO_ERROR;
	}

	return ret;
}

/**
 * read_char() - Read a char from file
 * @fp: [in] File pointer
 * @c: [out] char read
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End of file
 * RET_ERROR       - Error
 */
static int read_char(FILE *fp, int *c)
{
	int ret = RET_NO_ERROR;

	*c = getc(fp);
	if (ferror(fp))
		ret = RET_ERROR;
	else if (feof(fp))
		ret = RET_END_OF_FILE;

	return ret;
}

/**
 * read_line() - Read a significative line in the configuration file
 * @fp: [in] Pointer to configuration file
 * @line: [in/out] Buffer to read file line
 * @length: [in/out] length of @line buffer
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End of file
 * RET_ERROR       - Error
 */
static int read_line(FILE *fp, char **line, size_t *length)
{
	int ret = RET_NO_ERROR;

	ssize_t nread = 0;

	nread = getline(line, length, fp);

	if (nread < 0) {
		if (!feof(fp)) {
			DBG_PRINTF(ERROR, "%s (%d): %s\n", __func__, __LINE__,
				   get_strerr());
			ret = RET_ERROR;
		} else {
			ret = RET_END_OF_FILE;
		}
	}

	return ret;
}

/**
 * read_valid_entry() - Read a significative entry in the configuration file
 * @fp: [in] Pointer to configuration file
 * @line: [in/out] Buffer to read file line
 * @length: [in/out] length of @line buffer
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End Of File
 * RET_NEW_SECTION - Read new section
 * RET_ERROR       - Error
 */
static int read_valid_entry(FILE *fp, char **line, size_t *length)
{
	int ret = RET_NO_ERROR;
	int c = 0;
	bool comment = false;

	do {
		ret = read_char(fp, &c);
		if (ret)
			goto end;

		switch (c) {
		case TAG_SPACE:
		case TAG_CR:
		case TAG_LF:
			break;

		case TAG_COMMENT_HASH:
			if (comment)
				break;

			/* Comment on one line '#' */
			ret = read_line(fp, line, length);
			if (ret)
				goto end;

			break;

		case TAG_COMMENT_SLASH:
			if (comment)
				break;

			/*
			 * Start parsing a comment with '/'
			 * next character must be a '/' or '*'
			 * Read following character.
			 */
			ret = read_char(fp, &c);
			if (ret)
				goto end;

			switch (c) {
			case TAG_COMMENT_SLASH:
				/* Comment on one line '//' */
				ret = read_line(fp, line, length);
				if (ret)
					goto end;

				break;

			case TAG_COMMENT_STAR:
				/*
				 * One or multiple lines comment with
				 * potential '/' or '*' inside.
				 */
				comment = true;
				break;

			default:
				DBG_PRINTF(ERROR,
					   "%s (%d): invalid comment in file\n",
					   __func__, __LINE__);
				ret = RET_ERROR;
				goto end;
			}

			break;

		case TAG_COMMENT_STAR:
			if (comment) {
				/*
				 * Reading a comment, next character could be
				 * '/' to close commend, else continue to read
				 * the comment.
				 * Read following character.
				 */
				ret = read_char(fp, &c);
				if (ret)
					goto end;

				switch (c) {
				case TAG_COMMENT_SLASH:
					/* End of comment */
					comment = false;
					break;

				default:
					break;
				}

				break;
			}

			__fallthrough;

		default:
			if (comment)
				break;

			/* Read a valid entry */
			if (!fseek(fp, -1, SEEK_CUR)) {
				ret = read_line(fp, line, length);
				if (!ret && c == TAG_SECTION)
					ret = RET_NEW_SECTION;

			} else {
				ret = RET_ERROR;

				DBG_PRINTF(ERROR, "%s (%d): %s\n", __func__,
					   __LINE__, get_strerr());
			}

			goto end;
		}

	} while (c != EOF);

end:
	return ret;
}

/**
 * set_section_conf_value() - Set the value to the entry configuration
 * @config_flags: [in/out] Configuration flags
 * @cnf: [in/out] Section configuration descriptor
 * @field: [in] Configuration field to set
 * @value: [in] Value of the entry
 *
 * Return:
 * RET_NO_ERROR  - Success
 * RET_ERROR     - Error
 */
static int set_section_conf_value(unsigned int *config_flags,
				  const struct cnf_section_desc *cnf,
				  char *field, char *value)
{
	int ret = RET_NO_ERROR;
	const struct cnf_section_desc *entry = NULL;

	/* Increment value to skip the delimiter */
	for (entry = cnf; entry->entry; entry++) {
		if (!strncmp(field, entry->entry, strlen(entry->entry))) {
			if (!entry->conv) {
				ret = -1;
				break;
			}

			if (!(entry->flag & *config_flags)) {
				ret = entry->conv(entry->value, entry->length,
						  value);

				if (!ret)
					*config_flags |= entry->flag;
			}

			break;
		}
	}

	return ret;
}

/**
 * parse_section_conf() - Parse all section configuration entry
 * @fp: [in] Pointer to the configuration file
 * @config_flags: [in/out] Configuration flags
 * @cnf: [in/out] Configurations to find
 * @line: [out] Read line - return next section
 * @length: [in/out] length of @line buffer
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End Of File
 * RET_NEW_SECTION - Read new section
 * RET_ERROR       - Error
 */
static int parse_section_conf(FILE *fp, unsigned int *config_flags,
			      const struct cnf_section_desc *cnf, char **line,
			      size_t *length)
{
	int ret = RET_NO_ERROR;
	char *value = NULL;
	size_t conv_len = 0;

	do {
		ret = read_valid_entry(fp, line, length);
		if (ret != RET_NO_ERROR)
			break;

		/* Find the entry vs. value delimiter */
		value = strchr(*line, TAG_CNF_DELIM);
		if (!value)
			/* Undefined configuration, ignore the line */
			continue;

		/* Convert the entry value in lower case */
		if (SUB_OVERFLOW((uintptr_t)value, (uintptr_t)(*line),
				 &conv_len)) {
			ret = RET_ERROR;
			break;
		}

		string_to_lower(*line, conv_len);

		value++;

		ret = set_section_conf_value(config_flags, cnf, *line, value);
		if (ret)
			break;

	} while (!feof(fp));

	return ret;
}

/**
 * read_smw_conf() - Read the SMW Library subsystem configuration
 * @fp: [in] Pointer to configuration file
 * @config: [in/out] OSAL configuration context
 * @line: [out] Read line - return next section
 * @length: [in/out] length of @line buffer
 *
 * Read all configuration items and set for each the configuration flag
 * corresponding.
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End Of File
 * RET_NEW_SECTION - Read new section
 * RET_ERROR       - Error
 */
static int read_smw_conf(FILE *fp, struct lib_config_args *config, char **line,
			 size_t *length)
{
	int ret = RET_NO_ERROR;

	const struct cnf_section_desc cnf_section_smw[] = {
		{ SMW_CONFIG_FILE, &config->smw_info.smw_config_file, 0,
		  CONFIG_SMW_CONFIG_FILE, value_to_str_alloc },
		{ SMW_DATABASE, &config->smw_info.smw_database, 0,
		  CONFIG_SMW_DATABASE, value_to_str_alloc },
		{ NULL, NULL, 0, 0, NULL }
	};

	ret = parse_section_conf(fp, &config->config_flags, cnf_section_smw,
				 line, length);

	return ret;
}

/**
 * read_tee_conf() - Read the TEE subsystem configuration
 * @fp: [in] Pointer to configuration file
 * @config: [in/out] OSAL configuration context
 * @line: [out] Read line - return next section
 * @length: [in/out] length of @line buffer
 *
 * Read all subsystem configuration items, if one is missing, stop
 * without setting the configuration flags as set and exit with 0.
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End Of File
 * RET_NEW_SECTION - Read new section
 * RET_ERROR       - Error
 */
static int read_tee_conf(FILE *fp, struct lib_config_args *config, char **line,
			 size_t *length)
{
	int ret = RET_NO_ERROR;

	const struct cnf_section_desc cnf_section_tee[] = {
		{ TEE_CNF_TA_UUID, &config->tee_info.ta_uuid,
		  sizeof(config->tee_info.ta_uuid), CONFIG_TEE, value_to_str },
		{ NULL, NULL, 0, 0, NULL }
	};

	if (!(config->config_flags & CONFIG_TEE)) {
		ret = parse_section_conf(fp, &config->config_flags,
					 cnf_section_tee, line, length);
	}

	return ret;
}

/**
 * read_seco_conf() - Read the SECO subsystem configuration
 * @fp: [in] Pointer to configuration file
 * @config: [in/out] OSAL configuration context
 * @line: [out] Read line - return next section
 * @length: [in/out] length of @line buffer
 *
 * Read all subsystem configuration items, if one is missing, stop
 * without setting the configuration flags as set and exit with 0.
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End Of File
 * RET_NEW_SECTION - Read new section
 * RET_ERROR       - Error
 */
static int read_seco_conf(FILE *fp, struct lib_config_args *config, char **line,
			  size_t *length)
{
	int ret = RET_NO_ERROR;
	unsigned int seco_flags = 0;

#define FLAG_SECO_ID	 BIT(0)
#define FLAG_SECO_NONCE	 BIT(1)
#define FLAG_SECO_REPLAY BIT(2)

	const struct cnf_section_desc cnf_section_seco[] = {
		{ SECO_CNF_ID, &config->se_seco_info.storage_id, 0,
		  FLAG_SECO_ID, value_to_uint },
		{ SECO_CNF_NONCE, &config->se_seco_info.storage_nonce, 0,
		  FLAG_SECO_NONCE, value_to_uint },
		{ SECO_CNF_REPLAY, &config->se_seco_info.storage_replay, 0,
		  FLAG_SECO_REPLAY, value_to_ushort },
		{ NULL, NULL, 0, 0, NULL }
	};

	if (!(config->config_flags & CONFIG_SECO)) {
		ret = parse_section_conf(fp, &seco_flags, cnf_section_seco,
					 line, length);

		if (ret != RET_ERROR) {
			if (seco_flags ==
			    (FLAG_SECO_ID | FLAG_SECO_NONCE | FLAG_SECO_REPLAY))
				config->config_flags |= CONFIG_SECO;
		}
	}

	return ret;
}

/**
 * read_ele_conf() - Read the ELE subsystem configuration
 * @fp: [in] Pointer to configuration file
 * @config: [in/out] OSAL configuration context
 * @line: [out] Read line - return next section
 * @length: [in/out] length of @line buffer
 *
 * Read all subsystem configuration items, if one is missing, stop
 * without setting the configuration flags as set and exit with 0.
 *
 * Return:
 * RET_NO_ERROR    - Success
 * RET_END_OF_FILE - End Of File
 * RET_NEW_SECTION - Read new section
 * RET_ERROR       - Error
 */
static int read_ele_conf(FILE *fp, struct lib_config_args *config, char **line,
			 size_t *length)
{
	int ret = RET_NO_ERROR;
	unsigned int ele_flags = 0;

#define FLAG_ELE_ID    BIT(0)
#define FLAG_ELE_NONCE BIT(1)

	const struct cnf_section_desc cnf_section_ele[] = {
		{ ELE_CNF_ID, &config->se_ele_info.storage_id, 0, FLAG_ELE_ID,
		  value_to_uint },
		{ ELE_CNF_NONCE, &config->se_ele_info.storage_nonce, 0,
		  FLAG_ELE_NONCE, value_to_uint },
		{ NULL, NULL, 0, 0, NULL }
	};

	if (!(config->config_flags & CONFIG_ELE)) {
		ret = parse_section_conf(fp, &ele_flags, cnf_section_ele, line,
					 length);

		if (ret != RET_NO_ERROR) {
			if (ele_flags == (FLAG_ELE_ID | FLAG_ELE_NONCE))
				config->config_flags |= CONFIG_ELE;
		}
	}

	return ret;
}

const struct cnf_section {
	const char *name;
	int (*read_cnf)(FILE *fp, struct lib_config_args *cnf, char **line,
			size_t *length);
} cnf_sections[] = { { "[setup]", &read_smw_conf },
		     { "[tee]", &read_tee_conf },
		     { "[seco]", &read_seco_conf },
		     { "[ele]", &read_ele_conf },
		     { NULL, NULL } };

int config_read_system_cnf(void)
{
	int status = SMW_STATUS_OK;
	int ret = RET_NO_ERROR;
	FILE *fp = NULL;
	char *line = NULL;
	size_t length = 0;
	const struct cnf_section *section = NULL;

	struct osal_ctx *ctx = get_osal_ctx();

	if (!ctx)
		return SMW_STATUS_CONFIGURATION_FAILURE;

	fp = fopen(SMW_ETC_CNF, "r");
	if (!fp) {
		DBG_PRINTF(ERROR, "%s (%d): %s\n", __func__, __LINE__,
			   get_strerr());
		goto end;
	}

	do {
		if (ret != RET_NEW_SECTION) {
			/* Read the file until new section */
			ret = read_valid_entry(fp, &line, &length);
			if (ret == RET_END_OF_FILE) {
				goto end;
			} else if (ret == RET_ERROR) {
				status = SMW_STATUS_CONFIGURATION_FAILURE;
				goto end;
			} else if (ret != RET_NEW_SECTION) {
				continue;
			}
		}

		string_to_lower(line, strlen(line));

		for (section = cnf_sections; section->name; section++) {
			if (!strncmp(line, section->name,
				     strlen(section->name))) {
				if (!section->read_cnf) {
					status =
						SMW_STATUS_CONFIGURATION_FAILURE;
					goto end;
				}

				ret = section->read_cnf(fp, &ctx->config, &line,
							&length);

				if (ret == RET_ERROR) {
					status =
						SMW_STATUS_CONFIGURATION_FAILURE;
					goto end;
				}

				break;
			}
		}
	} while (!feof(fp));

end:
	if (line)
		free(line);

	if (fp && fclose(fp)) {
		DBG_PRINTF(ERROR, "%s (%d): %s\n", __func__, __LINE__,
			   get_strerr());

		if (status == SMW_STATUS_OK)
			status = SMW_STATUS_CONFIGURATION_FAILURE;
	}

	return status;
}

int config_smw_db(const char *file, struct lib_config_args *config)

{
	int ret = 0;

	ret = value_to_str_alloc(&config->smw_info.smw_database, 0,
				 (char *)file);
	if (!ret) {
		DBG_PRINTF(DEBUG, "%s (%d) %s=%s\n", __func__, __LINE__,
			   SMW_DATABASE, config->smw_info.smw_database);

		config->config_flags |= CONFIG_SMW_DATABASE;
	}

	return ret;
}
