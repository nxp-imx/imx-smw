// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw_device.h>
#include <smw_status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apis_dispatcher.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "lifecycle_table.h"
#include "logger.h"

/**
 * @brief Log SMW device lifecycle operation parameters
 *
 * @param args Pointer to smw_device_lifecycle_args structure
 */
static void
log_smw_dev_get_lifecycle_params(const struct smw_device_lifecycle_args *args)
{
	if (!args)
		return;

	LOG_INFO("=== smw_device_get_lifecycle Parameters ===");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  lifecycle_name: %d", args->lifecycle_name);
	LOG_INFO("===========================================");
}

/**
 * @brief Execute dev-get-lifecycle operation using SMW API
 *
 * Retrieves device lifecycle using smw_device_get_lifecycle().
 *
 * The function queries the current device lifecycle state and writes
 * the result to the specified file or stdout in text format.
 *
 * @param args Pointer to parsed command-line options structure
 */
enum cli_exit_code cli_dev_get_lifecycle_operation(struct parsed_options *args)
{
	struct smw_device_lifecycle_args lifecycle_args = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	const char *lifecycle_str = NULL;
	FILE *fp = NULL;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Device Lifecycle operation (SMW API)");

	/* Setup SMW device lifecycle arguments */
	lifecycle_args.version = 0;
	lifecycle_args.subsystem_name = args->subsystem;
	lifecycle_args.lifecycle_name = SMW_LIFECYCLE_NAME_NONE;

	log_smw_dev_get_lifecycle_params(&lifecycle_args);

	/* Get current lifecycle */
	status = smw_device_get_lifecycle(&lifecycle_args);
	if (!is_smw_api_success("smw_device_get_lifecycle", status))
		goto cleanup;

	lifecycle_str = lifecycle_name_to_string(lifecycle_args.lifecycle_name);

	LOG_INFO("Lifecycle: %s (%d)", lifecycle_str,
		 lifecycle_args.lifecycle_name);

	/* Write output to file if specified, otherwise print to stdout */
	if (args->output_filename) {
		fp = fopen(args->output_filename, "w");

		if (!fp) {
			LOG_ERROR("Failed to open output file: %s",
				  args->output_filename);
			goto cleanup;
		}
		fprintf(fp, "%s\n", lifecycle_str);
		fclose(fp);
		LOG_INFO("Lifecycle written to %s", args->output_filename);
	} else {
		printf("%s\n", lifecycle_str);
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	return ret;
}
