// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw_device.h>
#include <smw_status.h>
#include <stdio.h>
#include <stdlib.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "utils.h"

/**
 * @brief Log SMW device UUID operation parameters
 *
 * @param args Pointer to smw_device_uuid_args structure
 */
static void log_smw_device_uuid_params(const struct smw_device_uuid_args *args)
{
	if (!args)
		return;

	LOG_INFO("=== smw_device_get_uuid Parameters ===");
	LOG_INFO("  version           : %u", args->version);
	LOG_INFO("  subsystem_name    : %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  uuid              : %p", (void *)args->uuid);
	LOG_INFO("  uuid_length       : %u", args->uuid_length);
	LOG_INFO("  certificate       : %p", (void *)args->certificate);
	LOG_INFO("  certificate_length: %u", args->certificate_length);
	LOG_INFO("=======================================");
}

/**
 * @brief Execute dev-get-uuid operation using SMW API
 *
 * Retrieves device UUID using smw_device_get_uuid().
 *
 * The function performs a two-step query: first to get the required
 * buffer length, then to retrieve the actual UUID data. Output is
 * written to the specified file or stdout in binary or text format.
 *
 * @param args Pointer to parsed command-line options structure
 */
enum cli_exit_code cli_device_uuid_operation(struct parsed_options *args)
{
	unsigned char *uuid = NULL;
	struct smw_device_uuid_args device_args = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	FILE *fp = NULL;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Device UUID operation started (SMW API)");
	LOG_VERBOSE("  output_file : %s",
		    args->output_filename ? args->output_filename : "(stdout)");
	LOG_VERBOSE("  text_format : %s", args->text_format ? "yes" : "no");
	LOG_VERBOSE("  subsystem   : %s",
		    cli_smw_get_subsystem_name(args->subsystem));

	/* Setup SMW device UUID arguments for first call to get length */
	device_args.version = 0;
	device_args.subsystem_name = args->subsystem;
	device_args.certificate_length = 0;
	device_args.certificate = NULL;
	device_args.uuid = NULL;
	device_args.uuid_length = 0;

	LOG_VERBOSE("Step 1: Querying required UUID buffer length");
	log_smw_device_uuid_params(&device_args);

	/* First call: Get required UUID length */
	LOG_VERBOSE("Calling smw_device_get_uuid() (length query)");
	status = smw_device_get_uuid(&device_args);
	if (!is_smw_api_success("smw_device_get_uuid (query length)", status))
		goto cleanup;

	LOG_VERBOSE("Required UUID buffer length: %u bytes",
		    device_args.uuid_length);

	/* Allocate buffer for UUID */
	uuid = util_alloc_buffer(device_args.uuid_length, "device UUID");
	if (!uuid)
		goto cleanup;

	LOG_VERBOSE("UUID buffer allocated: %p (%u bytes)", (void *)uuid,
		    device_args.uuid_length);

	/* Second call: Get actual UUID */
	device_args.uuid = uuid;

	LOG_VERBOSE("Step 2: Retrieving actual UUID data");
	log_smw_device_uuid_params(&device_args);

	LOG_VERBOSE("Calling smw_device_get_uuid() (data retrieval)");
	status = smw_device_get_uuid(&device_args);
	if (!is_smw_api_success("smw_device_get_uuid", status))
		goto cleanup;

	SUCCESS("Get Device UUID");

	LOG_VERBOSE("UUID retrieved successfully (%u bytes)",
		    device_args.uuid_length);
	LOG_VERBOSE("Writing output data (%u bytes)", device_args.uuid_length);

	/* Write output */
	if (util_write_output_data(uuid, device_args.uuid_length,
				   args->output_filename, args->text_format)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (fp)
		FCLOSE(fp);

	if (uuid) {
		LOG_VERBOSE("Freeing UUID buffer");
		free(uuid);
	}

	return ret;
}
