/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __SMW_CONFIG_H__
#define __SMW_CONFIG_H__

/**
 * smw_config_subsystem_present() - Check if the subsystem is present or not.
 * @subsystem: Name of the subsystem
 *
 * Return:
 * SMW_STATUS_OK  Subsystem is present
 * error code otherwise
 */
int smw_config_subsystem_present(const char *subsystem);

/**
 * smw_config_check_digest() - Check if a digest @algo is supported
 * @subsystem: Name of the subsystem (if NULL default subsystem)
 * @algo: Digest algorithm name
 *
 * Function checks if the digest @algo is supported on the given @subsytem.
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * SMW_STATUS_OK                       Subsystem is present
 * SMW_STATUS_OPERATION_NOT_CONFIGURED Algorithm not supported
 * error code otherwise
 */
int smw_config_check_digest(const char *subsystem, const char *algo);

/**
 * struct smw_key_info - Key information
 * @key_type_name: Key type name
 * @security_size: Key security size in bits
 * @security_size_min: Key security size minimum in bits
 * @security_size_max: Key security size maximum in bits
 */
struct smw_key_info {
	const char *key_type_name;
	unsigned int security_size;
	unsigned int security_size_min;
	unsigned int security_size_max;
};

/**
 * smw_config_check_generate_key() - Check generate key type
 * @subsystem: Name of the subsystem (if NULL default subsystem)
 * @info: Key information
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given subsystem.
 *
 * If @info's security size field is equal 0, returns the security key
 * range size in bits supported by the subsystem for the key type. Else
 * checks if the security size is supported.
 *
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * SMW_STATUS_OK                       Subsystem is present
 * SMW_STATUS_OPERATION_NOT_CONFIGURED Algorithm not supported
 * error code otherwise
 */
int smw_config_check_generate_key(const char *subsystem,
				  struct smw_key_info *info);

#endif /* __SMW_CONFIG_H__ */
