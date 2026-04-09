// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */
#define _TIME_BITS	  64
#define _FILE_OFFSET_BITS 64

#include <smw_device.h>
#include <smw_status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apis_dispatcher.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "utils.h"

#define TIME_STR_SIZE 32
#define HEX_LINE_SIZE 64

/**
 * @brief Generate challenge from current date/time
 *
 * @param challenge Pointer to store generated challenge
 * @param challenge_len Pointer to store challenge length
 */
static int generate_date_challenge(unsigned char **challenge,
				   size_t *challenge_len)
{
	time_t now = 0;
	struct tm *timeinfo = NULL;
	char time_str[TIME_STR_SIZE] = { 0 };
	size_t len = 16;
	int written = 0;

	now = time(NULL);
	if (now == (time_t)-1) {
		LOG_ERROR("Failed to get current time");
		return -1;
	}

	timeinfo = localtime(&now);
	if (!timeinfo) {
		LOG_ERROR("Failed to get local time");
		return -1;
	}

	/* Format: YYMMDD HH:MM:SS (16 bytes with trailing space)
	 * YY   = year last 2 digits
	 * MM   = month
	 * DD   = day
	 * ' '  = space separator
	 * HH   = hour
	 * :    = colon
	 * MM   = minute
	 * :    = colon
	 * SS   = second
	 * ' '  = trailing space (padding)
	 */
	written =
		snprintf(time_str, sizeof(time_str),
			 "%02d.%02d.%02d%02d:%02d:%02d", timeinfo->tm_mday,
			 timeinfo->tm_mon + 1, timeinfo->tm_year % 100,
			 timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

	if (written != 16) {
		LOG_ERROR("Failed to format time string (got %d bytes)",
			  written);
		return -1;
	}

	*challenge = malloc(len);
	if (!*challenge) {
		LOG_ERROR("Failed to allocate challenge buffer");
		return -1;
	}

	memcpy(*challenge, time_str, len);
	*challenge_len = len;

	LOG_INFO("Generated 16-byte challenge from current date/time: %s",
		 time_str);
	return 0;
}

/**
 * @brief Log SMW device attestation operation parameters
 *
 * @param args Pointer to smw_device_attestation_args structure
 */
static void
log_smw_dev_attestation_params(const struct smw_device_attestation_args *args)
{
	unsigned int i = 0;
	char hex_line[HEX_LINE_SIZE] = { 0 };
	size_t offset = 0;
	int written = 0;

	if (!args)
		return;

	LOG_INFO("=== smw_device_attestation Parameters ===");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));

	/* Log challenge */
	if (args->challenge && args->challenge_length) {
		LOG_INFO("  challenge_length: %u", args->challenge_length);
		LOG_INFO("  challenge (hex):");
		for (i = 0; i < args->challenge_length; i++) {
			if (i % 16 == 0) {
				if (i > 0)
					LOG_INFO("    %s", hex_line);
				offset = 0;
				memset(hex_line, 0, sizeof(hex_line));
			}
			written = snprintf(hex_line + offset,
					   sizeof(hex_line) - offset, "%02X ",
					   args->challenge[i]);
			if (written > 0 &&
			    (size_t)written < (sizeof(hex_line) - offset))
				offset += (size_t)written;
			else
				break; /* Buffer full or error */
		}
		if (offset > 0)
			LOG_INFO("    %s", hex_line);
	} else {
		LOG_INFO("  challenge: NULL");
		LOG_INFO("  challenge_length: 0");
	}

	/* Log certificate */
	if (args->certificate && args->certificate_length) {
		LOG_INFO("  certificate_length: %u", args->certificate_length);
		LOG_INFO("  certificate: <binary data, %u bytes>",
			 args->certificate_length);
	} else {
		LOG_INFO("  certificate: NULL");
		LOG_INFO("  certificate_length: %u", args->certificate_length);
	}

	LOG_INFO("==========================================");
}

/**
 * @brief Execute dev-get-attestation operation using SMW API
 *
 * Retrieves device attestation certificate using smw_device_attestation().
 *
 * @param args Pointer to parsed command-line options structure
 */
enum cli_exit_code cli_device_attestation_operation(struct parsed_options *args)
{
	struct smw_device_attestation_args attest_args = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	unsigned char *challenge = NULL;
	size_t challenge_len = 0;
	unsigned char *certificate = NULL;
	FILE *fp = NULL;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Device Attestation operation (SMW API)");

	/* Read challenge if provided, otherwise generate from current date */
	if (args->op.dev_att.challenge_filename) {
		fp = fopen(args->op.dev_att.challenge_filename, "rb");
		if (!fp) {
			LOG_ERROR("Failed to open challenge file: %s",
				  args->op.dev_att.challenge_filename);
			goto cleanup;
		}

		/* Get file size */
		if (util_get_file_size(fp, &challenge_len,
				       args->op.dev_att.challenge_filename))
			goto cleanup;

		/* Allocate challenge buffer */
		challenge = util_alloc_buffer(challenge_len, "challenge");
		if (!challenge)
			goto cleanup;

		/* Read challenge data */
		if (fread(challenge, 1, challenge_len, fp) != challenge_len) {
			LOG_ERROR("Failed to read challenge file");
			goto cleanup;
		}

		FCLOSE(fp);
		fp = NULL;
		LOG_INFO("Challenge loaded from file: %zu bytes",
			 challenge_len);
	} else {
		printf("\nWarning: No challenge file provided, ");
		printf("using current date/time as 16-byte challenge\n\n");
		if (generate_date_challenge(&challenge, &challenge_len))
			goto cleanup;
	}

	/* Setup SMW device attestation arguments */
	attest_args.version = 0;
	attest_args.subsystem_name = args->subsystem;
	attest_args.challenge = challenge;

	if (challenge_len > UINT32_MAX) {
		LOG_ERROR("Challenge length %zu exceeds max supported size %u",
			  challenge_len, UINT32_MAX);
		goto cleanup;
	}

	attest_args.challenge_length = challenge_len;
	attest_args.certificate = NULL;
	attest_args.certificate_length = 0;

	/* First call to get required certificate length */
	status = smw_device_attestation(&attest_args);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_device_attestation (query length)",
					status))
			goto cleanup;
	}

	LOG_INFO("Required certificate length: %u",
		 attest_args.certificate_length);

	/* Allocate certificate buffer */
	certificate = util_alloc_buffer(attest_args.certificate_length,
					"certificate");
	if (!certificate)
		goto cleanup;

	/* Second call to get actual certificate */
	attest_args.certificate = certificate;

	log_smw_dev_attestation_params(&attest_args);

	status = smw_device_attestation(&attest_args);
	if (!is_smw_api_success("smw_device_attestation", status))
		goto cleanup;

	/* Write certificate to file or stdout */
	if (util_write_output_data(certificate, attest_args.certificate_length,
				   args->output_filename, args->text_format)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (fp)
		FCLOSE(fp);
	if (challenge)
		free(challenge);
	if (certificate)
		free(certificate);
	return ret;
}
