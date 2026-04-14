// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2026 NXP
 */

#include <stdbool.h>

#include "smw_config.h"
#include "smw_status.h"

#include "compiler.h"

__export __weak enum smw_status_code
smw_config_subsystem_present(smw_subsystem_t subsystem)
{
	(void)subsystem;

	return SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME;
}

__export __weak enum smw_status_code
smw_config_subsystem_loaded(smw_subsystem_t subsystem)
{
	(void)subsystem;

	return SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME;
}

__export __weak enum smw_status_code
smw_config_check_digest(smw_subsystem_t subsystem, smw_hash_algo_t algo)
{
	(void)subsystem;
	(void)algo;

	return SMW_STATUS_OPERATION_NOT_CONFIGURED;
}

__export __weak enum smw_status_code
smw_config_check_generate_key(smw_subsystem_t subsystem,
			      struct smw_key_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_derive_key(smw_subsystem_t subsystem, smw_kdf_t kdf)
{
	(void)subsystem;
	(void)kdf;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_cipher(smw_subsystem_t subsystem, struct smw_cipher_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_sign(smw_subsystem_t subsystem,
		      struct smw_signature_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_verify(smw_subsystem_t subsystem,
			struct smw_signature_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_aead(smw_subsystem_t subsystem, struct smw_aead_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_mac(smw_subsystem_t subsystem, struct smw_mac_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_asymmetric_encrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_asymmetric_decrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
