// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "helper.h"
#include "logger.h"
#include "pubkey_encode.h"
#include "utils.h"

#ifndef PUBKEY_CONVERT_SCRIPT
#error "PUBKEY_CONVERT_SCRIPT must be defined by the build system"
#endif

/**
 * @brief Run a command with explicit argument vector (avoids system()).
 *
 * @param argv  NULL-terminated argument vector
 */
static int run_script(const char *const argv[])
{
	pid_t pid;
	int wstatus;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}

	if (waitpid(pid, &wstatus, 0) < 0)
		return -1;

	if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0)
		return 0;

	return -1;
}

/**
 * @brief Write data to a temporary file using mkstemp
 *
 * @param data  Pointer to data buffer to write
 * @param len   Number of bytes to write
 * @param path  Template path for mkstemp (modified in place)
 */
static int write_temp(const uint8_t *data, size_t len, char *path)
{
	mode_t old_mask;
	int fd;

	if (len > (size_t)SSIZE_MAX)
		return -1;

	old_mask = umask(077);
	fd = mkstemp(path);
	(void)umask(old_mask);

	if (fd < 0)
		return -1;

	if (write(fd, data, len) != (ssize_t)len) {
		close(fd);
		unlink(path);
		return -1;
	}

	close(fd);
	return 0;
}

/**
 * @brief Encode a raw public key to DER or PEM and write to file.
 *
 * @param key_type  Key type string (e.g. "SECP_R1", "ED25519", "RSA")
 * @param bits      Key size in bits
 * @param raw       Raw public key bytes
 * @param raw_len   Length of raw key bytes
 * @param out_file  Output file path (user-specified)
 * @param use_pem   true for PEM, false for DER
 */
int pubkey_encode(const char *key_type, unsigned int bits, const uint8_t *raw,
		  size_t raw_len, const char *out_file, bool use_pem)
{
	char tmp[] = "/tmp/cli_raw_XXXXXX";
	char bits_str[16] = { 0 };
	const char *argv[13];

	if (write_temp(raw, raw_len, tmp)) {
		LOG_ERROR("Failed to write raw key to temp file");
		return -1;
	}

	SNPRINTF(bits_str, sizeof(bits_str), "%u", bits);

	argv[0] = "python3";
	argv[1] = PUBKEY_CONVERT_SCRIPT;
	argv[2] = "-t";
	argv[3] = key_type;
	argv[4] = "-b";
	argv[5] = bits_str;
	argv[6] = "-i";
	argv[7] = tmp;
	argv[8] = "-o";
	argv[9] = out_file;
	argv[10] = "-f";
	argv[11] = use_pem ? "pem" : "der";
	argv[12] = NULL;

	LOG_INFO("Running: python3 %s -t %s -b %s -i %s -o %s -f %s",
		 PUBKEY_CONVERT_SCRIPT, key_type, bits_str, tmp, out_file,
		 use_pem ? "pem" : "der");

	return run_script(argv) ? (unlink(tmp), -1) : (unlink(tmp), 0);
}

/**
 * @brief Encode an RSA public key (separate components) to DER or PEM.
 *
 * @param bits      Key size in bits
 * @param mod       RSA modulus bytes
 * @param mod_len   Modulus length
 * @param exp       RSA public exponent bytes
 * @param exp_len   Exponent length
 * @param out_file  Output file path (user-specified)
 * @param use_pem   true for PEM, false for DER
 */
int pubkey_encode_rsa(unsigned int bits, const uint8_t *mod, size_t mod_len,
		      const uint8_t *exp, size_t exp_len, const char *out_file,
		      bool use_pem)
{
	char tmp_mod[] = "/tmp/cli_mod_XXXXXX";
	char tmp_exp[] = "/tmp/cli_exp_XXXXXX";
	char bits_str[16] = { 0 };
	const char *argv[15];
	int ret = -1;
	const char *fmt =
		"Running: python3 %s -t RSA -b %s --modulus %s --exponent %s -o %s -f %s";

	if (write_temp(mod, mod_len, tmp_mod) ||
	    write_temp(exp, exp_len, tmp_exp)) {
		LOG_ERROR("Failed to write RSA components to temp files");
		goto out;
	}

	SNPRINTF(bits_str, sizeof(bits_str), "%u", bits);

	argv[0] = "python3";
	argv[1] = PUBKEY_CONVERT_SCRIPT;
	argv[2] = "-t";
	argv[3] = "RSA";
	argv[4] = "-b";
	argv[5] = bits_str;
	argv[6] = "--modulus";
	argv[7] = tmp_mod;
	argv[8] = "--exponent";
	argv[9] = tmp_exp;
	argv[10] = "-o";
	argv[11] = out_file;
	argv[12] = "-f";
	argv[13] = use_pem ? "pem" : "der";
	argv[14] = NULL;

	LOG_INFO(fmt, PUBKEY_CONVERT_SCRIPT, bits_str, tmp_mod, tmp_exp,
		 out_file, use_pem ? "pem" : "der");

	ret = run_script(argv);

out:
	unlink(tmp_mod);
	unlink(tmp_exp);
	return ret;
}
