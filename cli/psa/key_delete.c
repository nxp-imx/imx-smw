// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "helper.h"
#include "logger.h"
#include "parser_key_delete.h"

/**
 * @brief Log PSA key delete operation parameters
 *
 * @param key_id PSA key identifier to delete
 */
static void log_psa_key_delete_params(psa_key_id_t key_id)
{
	LOG_INFO("=== psa_destroy_key Parameters ===");
	LOG_INFO("  key_id:      0x%08x (%u)", key_id, key_id);
	LOG_INFO("==================================");
}

/**
 * @brief Print key delete result summary
 *
 * @param key_id Deleted key ID
 */
static void print_delete_result(psa_key_id_t key_id)
{
	SUCCESS("Key deletion");
	INFO("Key ID", "0x%08x (%u)", key_id, key_id);
	printf("\n");
}

/**
 * @brief Display help information for key delete (PSA API)
 */
void cli_key_delete_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Key Delete Operation - PSA API\n\n");

	cli_key_delete_help_common();

	printf("Example:\n");
	printf("  %s key-delete -i 20\n\n", prog_name);
}

/**
 * @brief Execute key deletion using PSA API
 *
 * Deletes a key from the secure subsystem using psa_destroy_key().
 * Key deletion is permanent and cannot be undone.
 *
 * The function destroys a key from both volatile memory and,
 * if applicable, non-volatile storage. The key identifier becomes
 * invalid after this call and must not be used again.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_key_delete_operation(struct parsed_options *args)
{
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	psa_key_id_t key_id = 0;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Key delete operation (PSA API)");

	key_id = (psa_key_id_t)args->op.key_delete.key_id;

	log_psa_key_delete_params(key_id);

	/* Call psa_destroy_key() */
	status = psa_destroy_key(key_id);
	if (!is_psa_api_success("psa_destroy_key", status))
		goto cleanup;

	print_delete_result(key_id);

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (args && args->log_filename) {
		free(args->log_filename);
		args->log_filename = NULL;
	}

	return ret;
}
