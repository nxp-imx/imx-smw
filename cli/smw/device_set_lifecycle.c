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

#define USAGE_STR 8

/**
 * @brief Log SMW device set lifecycle operation parameters
 *
 * @param args Pointer to smw_device_lifecycle_args structure
 */
static void
log_smw_dev_set_lifecycle_params(const struct smw_device_lifecycle_args *args)
{
	if (!args)
		return;

	LOG_INFO("=== smw_device_set_lifecycle Parameters ===");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  lifecycle_name: %s (%d)",
		 lifecycle_name_to_string(args->lifecycle_name),
		 args->lifecycle_name);
	LOG_INFO("===========================================");
}

/**
 * @brief Ask user to confirm the lifecycle change
 *
 * @param lifecycle_str String name of the target lifecycle
 */
static int confirm_lifecycle_change(const char *lifecycle_str)
{
	char input[USAGE_STR] = { 0 };

	printf("\n");
	printf("Warning: You are about to change the device lifecycle to: %s\n",
	       lifecycle_str);
	printf("This operation is IRREVERSIBLE.\n\n");
	printf("Type 'yes' to confirm, anything else to cancel: ");
	FFLUSH(stdout);

	if (!fgets(input, sizeof(input), stdin))
		return 0;

	/* Strip trailing newline */
	input[strcspn(input, "\n")] = '\0';

	return (!strcmp(input, "yes"));
}

/**
 * @brief Execute dev-set-lifecycle operation using SMW API
 *
 * Sets device lifecycle using smw_device_set_lifecycle().
 *
 * The function converts the lifecycle name string to its enum value,
 * prompts the user for confirmation, then applies the lifecycle change.
 *
 * @param args Pointer to parsed command-line options structure
 */
enum cli_exit_code cli_dev_set_lifecycle_operation(struct parsed_options *args)
{
	struct smw_device_lifecycle_args lifecycle_args = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	const char *lifecycle_str = NULL;
	smw_lifecycle_t target_lifecycle = SMW_LIFECYCLE_NAME_NONE;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Device Set Lifecycle operation (SMW API)");

	/* Convert lifecycle name string to enum value */
	target_lifecycle =
		string_to_lifecycle_name(args->op.dev_set_lc.lifecycle_name);
	if (target_lifecycle == SMW_LIFECYCLE_NAME_NONE) {
		LOG_ERROR("Unknown lifecycle. Use --list to see valid names.");
		goto cleanup;
	}

	lifecycle_str = lifecycle_name_to_string(target_lifecycle);

	/* Prompt user for explicit confirmation before applying */
	if (!confirm_lifecycle_change(lifecycle_str)) {
		printf("\nOperation cancelled by user.\n\n");
		ret = CLI_EXIT_SUCCESS;
		goto cleanup;
	}

	/* Setup SMW device lifecycle arguments */
	lifecycle_args.version = 0;
	lifecycle_args.subsystem_name = args->subsystem;
	lifecycle_args.lifecycle_name = target_lifecycle;

	log_smw_dev_set_lifecycle_params(&lifecycle_args);

	/* Set lifecycle */
	status = smw_device_set_lifecycle(&lifecycle_args);
	if (!is_smw_api_success("smw_device_set_lifecycle", status))
		goto cleanup;

	LOG_INFO("Lifecycle successfully set to: %s (%d)", lifecycle_str,
		 target_lifecycle);

	ret = CLI_EXIT_SUCCESS;

cleanup:
	return ret;
}
