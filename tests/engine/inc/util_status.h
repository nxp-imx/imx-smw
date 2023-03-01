/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __UTIL_STATUS_H__
#define __UTIL_STATUS_H__

/**
 * struct api_status_codes - API status codes
 * @status: API status integer value.
 * @string: API status string value.
 */
struct api_status_codes {
	int status;
	char *string;
};

/**
 * get_int_status() - Convert SMW status string value into integer value.
 * @status: Pointer to integer status to update. Not updated if an error
 *              is returned.
 * @string: Status string.
 * @api: API that returned the status.
 *
 * Return:
 * PASSED		- Success.
 * -UNKNOWN_RESULT	- @string is not present in status codes array.
 * -BAD_ARGS		- One of the argument is bad.
 */
int get_int_status(int *status, const char *string, const char *api);

/**
 * get_string_status() - Convert status integer value into string value.
 * @status: Status integer.
 * @api: API that returned the status.
 *
 * Return:
 * NULL	- Status doesn't exist.
 * SMW status string value otherwise.
 */
char *get_string_status(int status, const char *api);

#endif /* __UTIL_STATUS_H__ */
