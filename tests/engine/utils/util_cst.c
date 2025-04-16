// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "paths.h"
#include "util.h"
#include "util_cst.h"
#include "util_file.h"

int util_cst_is_present(void)
{
	int res = ERR_CODE(PASSED);
	DIR *dir = NULL;

	/* Check if the CST keys are installed, else skip the test */
	dir = opendir(CST_KEYS_DIR);
	if (!dir) {
		if (__errno_location() && errno == ENOENT)
			res = ERR_CODE(SKIPPED);
		else
			res = ERR_CODE(FAILED);

		DBG_PRINT("Open directory (%s): %s", CST_KEYS_DIR,
			  util_get_strerr());
		goto exit;
	}

	if (closedir(dir)) {
		DBG_PRINT("Closed directory (%s): %s", CST_KEYS_DIR,
			  util_get_strerr());
		res = ERR_CODE(FAILED);
	}

exit:
	return res;
}

int util_cst_create_files(const char *bin_file, const char *csf_file,
			  char *data, unsigned int length)
{
	int res = ERR_CODE(PASSED);
	char template_csf[] = "template_signed_msg.csf";
	char sign_offset[10] = { 0 };

	res = util_file_append_buffer(CST_WORKING_DIR, bin_file, "w", data,
				      length);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Set the binary file name to sign in the CSF file */
	res = util_file_replace(CST_WORKING_DIR, template_csf, csf_file,
				"REPLACE_CONTAINER", bin_file);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Set the offset of the signature in the CSF file */
	if (sprintf(sign_offset, "0x%X", length) < 0) {
		DBG_PRINT("sprintf error: %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	res = util_file_replace(CST_WORKING_DIR, csf_file, csf_file,
				"REPLACE_SIGN_OFFSET", sign_offset);
exit:
	return res;
}

int util_cst_sign(char *const bin_file, char *const csf_file)
{
	int ret = ERR_CODE(FAILED);

	char *const cmd[] = { "cst", "-o", bin_file, "-i", csf_file, NULL };
	char cwd[PATH_MAX] = { 0 };

	ret = util_app_find_exe("cst");
	if (ret != ERR_CODE(PASSED)) {
		DBG_PRINT("Executable cst not installed");
		ret = ERR_CODE(SKIPPED);
		goto exit;
	}

	if (getcwd(cwd, sizeof(cwd)) != cwd) {
		DBG_PRINT("Getting cwd error %s", util_get_strerr());
		goto exit;
	}

	if (chdir(CST_WORKING_DIR)) {
		DBG_PRINT("chdir (%s) error %s", CST_WORKING_DIR,
			  util_get_strerr());
		goto exit;
	}

	ret = util_app_exe_system(cmd);

exit:
	if (strlen(cwd) && chdir(cwd))
		DBG_PRINT("chdir (%s) error %s", cwd, util_get_strerr());

	return ret;
}
