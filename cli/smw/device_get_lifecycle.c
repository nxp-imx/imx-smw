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
#include "cli_print.h"
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
	LOG_INFO("  version        : %u", args->version);
	LOG_INFO("  subsystem_name : %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  lifecycle_name : %d", args->lifecycle_name);
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

	LOG_INFO("Device lifecycle operation started (SMW API)");
	LOG_VERBOSE("  output_file : %s",
		    args->output_filename ? args->output_filename : "(stdout)");
	LOG_VERBOSE("  subsystem   : %s",
		    cli_smw_get_subsystem_name(args->subsystem));

	/* Setup SMW device lifecycle arguments */
	lifecycle_args.version = 0;
	lifecycle_args.subsystem_name = args->subsystem;
	lifecycle_args.lifecycle_name = SMW_LIFECYCLE_NAME_NONE;

	/* Log SMW API parameters */
	log_smw_dev_get_lifecycle_params(&lifecycle_args);

	/* Call SMW API to get current lifecycle */
	LOG_VERBOSE("Calling smw_device_get_lifecycle()");
	status = smw_device_get_lifecycle(&lifecycle_args);
	if (!is_smw_api_success("smw_device_get_lifecycle", status))
		goto cleanup;

	/* Convert lifecycle enum to string */
	lifecycle_str = lifecycle_name_to_string(lifecycle_args.lifecycle_name);

	LOG_VERBOSE("Lifecycle value returned: %d",
		    lifecycle_args.lifecycle_name);

	SUCCESS("Get Device Lifecycle");

	/* Write output to file if specified, otherwise print to stdout */
	if (args->output_filename) {
		LOG_VERBOSE("Opening output file: %s", args->output_filename);

		fp = fopen(args->output_filename, "w");
		if (!fp) {
			LOG_ERROR("Failed to open output file: %s",
				  args->output_filename);
			goto cleanup;
		}

		FPRINTF(fp, "%s\n", lifecycle_str);
		FCLOSE(fp);
		fp = NULL;

		LOG_VERBOSE("Lifecycle written to file: %s",
			    args->output_filename);
	} else {
		LOG_VERBOSE("Writing lifecycle to stdout");
		printf("%s\n", lifecycle_str);
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (fp)
		FCLOSE(fp);

	return ret;
}
