// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <stdint.h>
#include <stddef.h>

#include <smw_status.h>
#include <smw_osal.h>

int32_t val_entry(void);

/**
 * main() - PSA Architecture Testsuite main function.
 * @argc: The number of command line arguments.
 * @argv: Array containing command line arguments.
 *
 * Return:
 * error status
 */
int main(int argc, char **argv)
{
	enum smw_status_code status;

	(void)argc;
	(void)argv;

	struct se_info {
		unsigned int storage_id;
		unsigned int storage_nonce;
		unsigned short storage_replay;
	} se_default_info = { 0x50534154, 0x444546, 1000 }; // PSA, DEF

	struct tee_info {
		char ta_uuid[37];
	} tee_default_info = { { "1682dada-20de-4b02-9eaa-284776931233" } };

	status = smw_osal_set_subsystem_info("HSM", &se_default_info,
					     sizeof(se_default_info));
	if (status != SMW_STATUS_OK)
		return -1;

	status = smw_osal_set_subsystem_info("TEE", &tee_default_info,
					     sizeof(tee_default_info));
	if (status != SMW_STATUS_OK)
		return -1;

	status = smw_osal_lib_init();
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_LIBRARY_ALREADY_INIT)
		return -1;

	return val_entry();
}
