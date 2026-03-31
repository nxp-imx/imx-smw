// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw_device.h>
#include <smw_status.h>
#include <stdio.h>
#include <stdlib.h>
#include "apis_dispatcher.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "utils.h"

/**
 * @brief Log SMW device UUID operation parameters
 *
 * @param args: Pointer to smw_device_uuid_args structure
 */
static void log_smw_device_uuid_params(const struct smw_device_uuid_args *args)
{
	if (!args)
		return;

	LOG_INFO("=== smw_device_get_uuid Parameters ===");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  uuid: %p", (void *)args->uuid);
	LOG_INFO("  uuid_length: %u", args->uuid_length);
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

	LOG_INFO("Device UUID operation (SMW API)");

	/* Setup SMW device UUID arguments for first call to get length */
	device_args.version = 0;
	device_args.subsystem_name = args->subsystem;
	device_args.certificate_length = 0;
	device_args.certificate = NULL;
	device_args.uuid = NULL;
	device_args.uuid_length = 0;

	/* First call: Get required UUID length */
	status = smw_device_get_uuid(&device_args);
	if (!is_smw_api_success("smw_device_get_uuid (query length)", status))
		goto cleanup;

	/* Allocate buffer for UUID */
	uuid = util_alloc_buffer(device_args.uuid_length, "device UUID");
	if (!uuid)
		goto cleanup;

	/* Second call: Get actual UUID */
	device_args.uuid = uuid;

	log_smw_device_uuid_params(&device_args);

	status = smw_device_get_uuid(&device_args);
	if (!is_smw_api_success("smw_device_get_uuid", status))
		goto cleanup;

	/* Write output */
	if (util_write_output_data(uuid, device_args.uuid_length,
				   args->output_filename, args->text_format)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (fp)
		FCLOSE(fp);

	if (uuid)
		free(uuid);

	return ret;
}
