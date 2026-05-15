// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <smw_keymgr.h>
#include <smw_status.h>
#include "apis_dispatcher.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "parser_key_delete.h"

/**
 * @brief Log SMW key delete operation parameters
 *
 * @param args Pointer to SMW delete key arguments structure
 */
static void log_smw_key_delete_params(const struct smw_delete_key_args *args)
{
	if (!args || !args->key_descriptor)
		return;

	LOG_INFO("=== smw_delete_key Parameters (smw_delete_key_args) ===");
	LOG_INFO("  version:          %u", args->version);
	LOG_INFO("  key_id:           0x%08x (%u)", args->key_descriptor->id,
		 args->key_descriptor->id);
	LOG_INFO("=======================================================");
}

/**
 * @brief Print key delete result summary
 *
 * @param key_id Deleted key ID
 */
static void print_delete_result(unsigned int key_id)
{
	printf("\n");
	printf("Key deleted successfully\n");
	printf("========================\n");
	printf("Key ID: 0x%08x (%u)\n", key_id, key_id);
	printf("\n");
}

/**
 * @brief Display help information for key delete (SMW API)
 */
void cli_key_delete_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Key Delete Operation - SMW API\n\n");

	cli_key_delete_help_common();

	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("\nExample:\n");
	printf("  %s key-delete -i 20\n\n", prog_name);
}

/**
 * @brief Execute key deletion using SMW API
 *
 * Deletes a key from the secure subsystem using smw_delete_key().
 * Key deletion is permanent and cannot be undone.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_key_delete_operation(struct parsed_options *args)
{
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_delete_key_args delete_args = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Key delete operation (SMW API)");

	/* Set up key descriptor with the given key ID */
	key_desc.id = args->op.key_delete.key_id;
	key_desc.type_name = SMW_KEY_TYPE_NAME_NONE;
	key_desc.security_size = 0;
	key_desc.buffer = NULL;

	/* Set up delete arguments */
	delete_args.version = 0;
	delete_args.key_descriptor = &key_desc;

	log_smw_key_delete_params(&delete_args);

	/* Call smw_delete_key() */
	status = smw_delete_key(&delete_args);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_delete_key", status))
			goto cleanup;
	}

	print_delete_result(key_desc.id);

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (args && args->log_filename) {
		free(args->log_filename);
		args->log_filename = NULL;
	}

	return ret;
}
