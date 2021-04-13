/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

enum smw_config_key_type_id {
	/* Key type IDs */
	SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
	SMW_CONFIG_KEY_TYPE_ID_AES,
	SMW_CONFIG_KEY_TYPE_ID_DES,
	SMW_CONFIG_KEY_TYPE_ID_DES3,
	SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP,
	SMW_CONFIG_KEY_TYPE_ID_SM4,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3,
	SMW_CONFIG_KEY_TYPE_ID_RSA,
	SMW_CONFIG_KEY_TYPE_ID_NB,
	SMW_CONFIG_KEY_TYPE_ID_INVALID
};

enum smw_config_hash_algo_id {
	SMW_CONFIG_HASH_ALGO_ID_MD5,
	SMW_CONFIG_HASH_ALGO_ID_SHA1,
	SMW_CONFIG_HASH_ALGO_ID_SHA224,
	SMW_CONFIG_HASH_ALGO_ID_SHA256,
	SMW_CONFIG_HASH_ALGO_ID_SHA384,
	SMW_CONFIG_HASH_ALGO_ID_SHA512,
	SMW_CONFIG_HASH_ALGO_ID_SM3,
	SMW_CONFIG_HASH_ALGO_ID_NB,
	SMW_CONFIG_HASH_ALGO_ID_INVALID
};

enum smw_config_hmac_algo_id {
	SMW_CONFIG_HMAC_ALGO_ID_MD5,
	SMW_CONFIG_HMAC_ALGO_ID_SHA1,
	SMW_CONFIG_HMAC_ALGO_ID_SHA224,
	SMW_CONFIG_HMAC_ALGO_ID_SHA256,
	SMW_CONFIG_HMAC_ALGO_ID_SHA384,
	SMW_CONFIG_HMAC_ALGO_ID_SHA512,
	SMW_CONFIG_HMAC_ALGO_ID_SM3,
	SMW_CONFIG_HMAC_ALGO_ID_NB,
	SMW_CONFIG_HMAC_ALGO_ID_INVALID
};

enum smw_config_sign_type_id {
	SMW_CONFIG_SIGN_TYPE_ID_DEFAULT,
	SMW_CONFIG_SIGN_TYPE_ID_RSASSA_PKCS1_V1_5,
	SMW_CONFIG_SIGN_TYPE_ID_RSASSA_PSS,
	SMW_CONFIG_SIGN_TYPE_ID_NB
};

/**
 * smw_config_init() - Initialize the Configuration module.
 *
 * This function initializes the Configuration module.
 *
 * Return:
 * error code.
 */
int smw_config_init(void);

/**
 * smw_config_deinit() - Deinitialize the Configuration module.
 *
 * This function deinitializes the Configuration module.
 *
 * Return:
 * error code.
 */
int smw_config_deinit(void);

/**
 * smw_config_get_subsystem_caps() - Get capabilities.
 * @subsystem_id: Pointer to a Secure Subsystem ID.
 * @operation_id: Security Operation ID.
 * @params: Address of a pointer pointing to the data structure
 *          that describes the capabilities.
 *
 * If @subsystem_id is set invalid, this function sets it
 * to the default Secure Subsystem configured for the Security Operation.
 * Then this function gets the capabilities configured for
 * this Secure Operation.
 *
 * Return:
 * error code.
 */
int smw_config_get_subsystem_caps(enum subsystem_id *subsystem_id,
				  enum operation_id operation_id,
				  void **params);

/**
 * smw_config_load_subsystem() - Load a Secure Subsystem.
 * @id: Secure Subsystem ID.
 *
 * This function loads a Secure Subsystem.
 *
 * Return:
 * error code.
 */
int smw_config_load_subsystem(enum subsystem_id id);

/**
 * smw_config_unload_subsystem() - Unload a Secure Subsystem.
 * @id: Secure Subsystem ID.
 *
 * This function unloads a Secure Subsystem.
 *
 * Return:
 * error code.
 */
int smw_config_unload_subsystem(enum subsystem_id id);

/**
 * smw_config_notify_subsystem_failure() - Notify subsystem failure.
 * @id: ID of the subsystem.
 *
 * This function notifies about a subsystem failure.
 * It is called by the subsystem module when the subsystem has encountered
 * a failure so that the configuration module can take appropriate action.
 *
 * Return:
 * none.
 */
void smw_config_notify_subsystem_failure(enum subsystem_id id);

/**
 * smw_config_get_operation_func() - Get the Security Operation functions.
 * @operation_id: Security Operation ID.
 *
 * This function gets a Security Operation functions.
 *
 * Return:
 * * pointer to the data structure containing the functions pointers
 *   associated with the Security Operation.
 */
struct operation_func *smw_config_get_operation_func(enum operation_id id);

/**
 * smw_config_get_subsystem_func() - Get the Secure Subsystem functions.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function gets a Secure Subsystem functions.
 *
 * Return:
 * * pointer to the data structure containing the functions pointers
 *   associated with the Secure Subsystem.
 */
struct subsystem_func *smw_config_get_subsystem_func(enum subsystem_id id);

/**
 * smw_config_get_operation_name() - Get the Security Operation name.
 * @operation_id: Security Operation ID.
 *
 * This function gets the name of a Security Operation.
 *
 * Return:
 * pointer to the string that is the Security Operation name.
 */
const char *smw_config_get_operation_name(enum operation_id id);

/**
 * smw_config_get_subsystem_name() - Get the Secure Subsystem name.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function gets the name of a Secure Subsystem.
 *
 * Return:
 * pointer to the string that is the Secure Subsystem name.
 */
const char *smw_config_get_subsystem_name(enum subsystem_id id);

/**
 * smw_config_get_subsystem_id() - Get the ID associated to a name.
 * @name: Name of the Secure Subsystem.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID of a Secure Subsystem designated by its name.
 *
 * Return:
 * error code.
 */
int smw_config_get_subsystem_id(const char *name, enum subsystem_id *id);

/**
 * smw_config_get_key_type_id() - Get the ID associated to a Key type name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID associated to a Key type name.
 *
 * Return:
 * error code.
 */
int smw_config_get_key_type_id(const char *name,
			       enum smw_config_key_type_id *id);

/**
 * smw_config_get_key_type_name() - Get the name associated to a Key type ID.
 * @id: Key type ID.
 * @name: Pointer to the Key type name.
 *
 * This function gets the name associated to a Key type ID.
 *
 * Return:
 * none.
 */
void smw_config_get_key_type_name(enum smw_config_key_type_id id,
				  const char **name);

/**
 * smw_config_get_hash_algo_id() - Get the Hash algo ID associated to a name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the Hash algo ID associated to a name.
 *
 * Return:
 * error code.
 */
int smw_config_get_hash_algo_id(const char *name,
				enum smw_config_hash_algo_id *id);

/**
 * smw_config_get_hmac_algo_id() - Get the HMAC algo ID associated to a name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the HMAC algo ID associated to a name.
 *
 * Return:
 * error code.
 */
int smw_config_get_hmac_algo_id(const char *name,
				enum smw_config_hmac_algo_id *id);

/**
 * smw_config_get_signature_type_id() - Get the signature type ID associated to
 *                                      a name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_signature_type_id(const char *name,
				     enum smw_config_sign_type_id *id);
