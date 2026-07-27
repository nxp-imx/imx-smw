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

	LOG_VERBOSE("Forking process to run: %s", argv[0]);

	pid = fork();
	if (pid < 0) {
		LOG_ERROR("fork() failed");
		return -1;
	}

	if (pid == 0) {
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}

	LOG_VERBOSE("Child process PID: %d", (int)pid);

	if (waitpid(pid, &wstatus, 0) < 0) {
		LOG_ERROR("waitpid() failed for PID %d", (int)pid);
		return -1;
	}

	if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) {
		LOG_VERBOSE("Child process exited successfully");
		return 0;
	}

	LOG_ERROR("Child process exited with status %d",
		  WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);

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

	if (len > (size_t)SSIZE_MAX) {
		LOG_ERROR("Data length %zu exceeds SSIZE_MAX", len);
		return -1;
	}

	old_mask = umask(077);
	fd = mkstemp(path);
	(void)umask(old_mask);

	if (fd < 0) {
		LOG_ERROR("mkstemp() failed for template: %s", path);
		return -1;
	}

	LOG_VERBOSE("Temporary file created: %s (fd=%d)", path, fd);

	if (write(fd, data, len) != (ssize_t)len) {
		LOG_ERROR("Failed to write %zu bytes to temp file: %s", len,
			  path);
		close(fd);
		unlink(path);
		return -1;
	}

	LOG_VERBOSE("Written %zu bytes to temp file: %s", len, path);

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

	LOG_VERBOSE("%s: key_type=%s bits=%u raw_len=%zu out_file=%s format=%s",
		    __func__, key_type, bits, raw_len, out_file,
		    use_pem ? "pem" : "der");

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

	if (run_script(argv)) {
		unlink(tmp);
		LOG_ERROR("%s script failed for key_type=%s bits=%u format=%s",
			  __func__, key_type, bits, use_pem ? "pem" : "der");
		return -1;
	}

	unlink(tmp);
	LOG_VERBOSE("Temp file removed: %s", tmp);
	LOG_VERBOSE("%s completed successfully: output=%s", __func__, out_file);

	return 0;
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

	LOG_VERBOSE("%s: bits=%u mod_len=%zu exp_len=%zu out_file=%s format=%s",
		    __func__, bits, mod_len, exp_len, out_file,
		    use_pem ? "pem" : "der");

	if (write_temp(mod, mod_len, tmp_mod)) {
		LOG_ERROR("Failed to write RSA modulus to temp file");
		goto out;
	}

	if (write_temp(exp, exp_len, tmp_exp)) {
		LOG_ERROR("Failed to write RSA exponent to temp file");
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

	if (ret)
		LOG_ERROR("%s script failed: bits=%u format=%s", __func__, bits,
			  use_pem ? "pem" : "der");
	else
		LOG_VERBOSE("%s completed successfully: output=%s", __func__,
			    out_file);

out:
	unlink(tmp_mod);
	unlink(tmp_exp);
	LOG_VERBOSE("Temp files removed: %s %s", tmp_mod, tmp_exp);

	return ret;
}
