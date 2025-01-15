// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_status.h"

#include "common.h"

static const char *const cipher_mode_strings[] = {
	[SMW_CONFIG_CIPHER_MODE_ID_CBC] = "CBC",
	[SMW_CONFIG_CIPHER_MODE_ID_CFB] = "CFB",
	[SMW_CONFIG_CIPHER_MODE_ID_CTR] = "CTR",
	[SMW_CONFIG_CIPHER_MODE_ID_CTS] = "CTS",
	[SMW_CONFIG_CIPHER_MODE_ID_ECB] = "ECB",
	[SMW_CONFIG_CIPHER_MODE_ID_XTS] = "XTS"
};

int read_cipher_mode_strings(char **start, char *end, unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, cipher_mode_strings,
					SMW_CONFIG_CIPHER_MODE_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_MODE_NAME;

	return status;
}
