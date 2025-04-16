/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __UTIL_CST_H__
#define __UTIL_CST_H__

/**
 * util_cst_is_present() - Check if the CST tool is present
 *
 * Return:
 * PASSED                  - Success.
 * -SKIPPED                - CST tool not present
 * -FAILED                 - System command failed
 */
int util_cst_is_present(void);

/**
 * util_cst_create_files() - Create the binary and csf file
 * @bin_file: Fullpath to the output binary file signed
 * @csf_file: Fullpath to the input CST text file
 * @data: Data to add in the @bin_file
 * @length: Length of @data
 *
 * Return:
 * PASSED                  - Success.
 * -INTERNAL               - Operation failure
 * -FAILED                 - System command failed
 */
int util_cst_create_files(const char *bin_file, const char *csf_file,
			  char *data, unsigned int length);

/**
 * util_cst_sign() - Sign binary with CST tool
 * @bin_file: Fullpath to the output binary file signed
 * @csf_file: Fullpath to the input CST text file
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL               - Fork operation failure
 * -FAILED                 - System command failed
 */
int util_cst_sign(char *const bin_file, char *const csf_file);

#endif /* __UTIL_CST_H__ */
