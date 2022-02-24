// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2022 NXP
 */

#include "local.h"

#include "smw_config.h"
#include "smw_osal.h"

__attribute__((destructor)) static void destructor(void);

struct osal_priv osal_priv = { 0 };

int mutex_init(void **mutex)
{
	int status = -1;

	TRACE_FUNCTION_CALL;

	if (!mutex)
		goto end;
	if (*mutex)
		goto end;

	*mutex = malloc(sizeof(pthread_mutex_t));
	if (!*mutex)
		goto end;

	status = pthread_mutex_init((pthread_mutex_t *)*mutex, NULL);

end:
	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int mutex_destroy(void **mutex)
{
	int status = -1;

	TRACE_FUNCTION_CALL;

	if (!mutex)
		goto end;
	if (!*mutex)
		goto end;

	status = pthread_mutex_destroy((pthread_mutex_t *)*mutex);
	if (status)
		goto end;

	free(*mutex);
	*mutex = NULL;

end:
	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int mutex_lock(void *mutex)
{
	int status = -1;

	TRACE_FUNCTION_CALL;

	status = pthread_mutex_lock((pthread_mutex_t *)mutex);

	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int mutex_unlock(void *mutex)
{
	int status = -1;

	TRACE_FUNCTION_CALL;

	status = pthread_mutex_unlock((pthread_mutex_t *)mutex);

	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int thread_create(unsigned long *thread, void *(*start_routine)(void *),
			 void *arg)
{
	return pthread_create(thread, NULL, start_routine, arg);
}

static int thread_cancel(unsigned long thread)
{
	return pthread_cancel(thread);
}

static unsigned long thread_self(void)
{
	return (unsigned long)pthread_self();
}

static void register_active_subsystem(const char *subsystem_name)
{
	TRACE_FUNCTION_CALL;

	osal_priv.active_subsystem_name = subsystem_name;
}

static int set_tee_info(void *info, size_t info_size)
{
	if (info_size != sizeof(struct tee_info))
		return SMW_STATUS_INVALID_PARAM;

	osal_priv.config.tee_info = *((struct tee_info *)info);
	osal_priv.config.config_flags |= CONFIG_TEE;

	return SMW_STATUS_OK;
}

static int get_tee_info(struct tee_info *info)
{
	int ret = -1;

	/*
	 * Copy the TEE configuration if value set
	 * in the library instance
	 */
	if (osal_priv.config.config_flags & CONFIG_TEE) {
		*info = osal_priv.config.tee_info;
		ret = 0;
	}

	return ret;
}

static int set_hsm_info(void *info, size_t info_size)
{
	if (info_size != sizeof(struct se_info))
		return SMW_STATUS_INVALID_PARAM;

	osal_priv.config.se_info = *((struct se_info *)info);
	osal_priv.config.config_flags |= CONFIG_SE;

	return SMW_STATUS_OK;
}

static int get_hsm_info(struct se_info *info)
{
	int ret = -1;

	/*
	 * Copy the Storage Nonce configuration if value set
	 * in the library instance
	 */
	if (osal_priv.config.config_flags & CONFIG_SE) {
		*info = osal_priv.config.se_info;
		ret = 0;
	}

	return ret;
}

static int get_subsystem_info(const char *subsystem_name, void *info)
{
	TRACE_FUNCTION_CALL;

	if (!info || !subsystem_name)
		return -1;

	if (!strcmp(subsystem_name, "TEE"))
		return get_tee_info(info);

	if (!strcmp(subsystem_name, "HSM"))
		return get_hsm_info(info);

	DBG_PRINTF(VERBOSE, "%s unknown %s subsystem\n", __func__,
		   subsystem_name);

	return -1;
}

static bool is_lib_initialized(void)
{
	return osal_priv.lib_initialized;
}

static int get_default_config(char **buffer, unsigned int *size)
{
	int status = SMW_STATUS_NO_CONFIG_LOADED;
	long fsize;

	FILE *f = NULL;
	const char *file_name = getenv("SMW_CONFIG_FILE");

	TRACE_FUNCTION_CALL;

	if (!file_name) {
		DBG_PRINTF(ERROR, "SMW_CONFIG_FILE not set.\n"
				  "Use export SMW_CONFIG_FILE=...\n");
		goto end;
	}

	f = fopen(file_name, "r");
	if (!f)
		goto end;

	if (fseek(f, 0, SEEK_END)) {
		if (ferror(f))
			perror("fseek() SEEK_END");
		goto end;
	}

	fsize = ftell(f);
	if (fsize == -1) {
		if (ferror(f))
			perror("ftell()");
		goto end;
	}
	DBG_PRINTF(INFO, "File size: %ld\n", fsize);

	/* Check of file size is not too big */
	if (fsize > (long)(UINT16_MAX - 1)) {
		DBG_PRINTF(ERROR, "File size too big\n");
		goto end;
	}

	*size = fsize;
	if (fseek(f, 0, SEEK_SET)) {
		if (ferror(f))
			perror("fseek() SEEK_SET");
		goto end;
	}

	*buffer = malloc(*size + 1);
	if (!*buffer)
		goto end;
	if (*size != fread(*buffer, sizeof **buffer, *size, f)) {
		if (feof(f)) {
			DBG_PRINTF(ERROR, "Error reading %s: unexpected EOF\n",
				   file_name);
			goto end;
		}

		if (ferror(f))
			perror("fread()");

		goto end;
	}
	*(*buffer + *size) = '\0';
	DBG_PRINTF(INFO, "Plaintext configuration (size: %d):\n%.*s\n", *size,
		   *size, *buffer);

	status = SMW_STATUS_OK;

end:
	if (f)
		if (fclose(f))
			perror("fclose()");

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int stop(void)
{
	int status = 0;

	TRACE_FUNCTION_CALL;

	status = smw_config_unload();
	if (status)
		goto end;

	status = smw_deinit();

	key_db_close();

end:
	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void destructor(void)
{
	stop();
}

__export __weak const char *smw_osal_latest_subsystem_name(void)
{
	return NULL;
}

__export enum smw_status_code
smw_osal_set_subsystem_info(smw_subsystem_t subsystem, void *info,
			    size_t info_size)
{
	int status;

	if (!subsystem || !info)
		return SMW_STATUS_INVALID_PARAM;

	status = smw_config_subsystem_loaded(subsystem);
	if (status != SMW_STATUS_SUBSYSTEM_LOADED) {
		if (!strcmp(subsystem, "TEE"))
			status = set_tee_info(info, info_size);
		else if (!strcmp(subsystem, "HSM"))
			status = set_hsm_info(info, info_size);
		else
			status = SMW_STATUS_UNKNOWN_NAME;
	}

	return status;
}

__export enum smw_status_code smw_osal_open_key_db(const char *file,
						   size_t len __maybe_unused)
{
	DBG_PRINTF(INFO, "Open Key database %s (%zu)\n", file, len);

	if (key_db_open(file)) {
		DBG_PRINTF(ERROR, "Error opening/creating key db %s\n", file);
		return SMW_STATUS_KEY_DB_INIT;
	}

	return SMW_STATUS_OK;
}

__export enum smw_status_code smw_osal_lib_init(void)
{
	int status;

	struct smw_ops ops = { 0 };
	char *buffer = NULL;
	unsigned int size = 0;
	unsigned int offset = 0;

	TRACE_FUNCTION_CALL;

	if (osal_priv.lib_initialized)
		return SMW_STATUS_LIBRARY_ALREADY_INIT;

	ops.mutex_init = mutex_init;
	ops.mutex_destroy = mutex_destroy;
	ops.mutex_lock = mutex_lock;
	ops.mutex_unlock = mutex_unlock;
	ops.thread_create = thread_create;
	ops.thread_cancel = thread_cancel;
	ops.thread_self = thread_self;
	ops.register_active_subsystem = register_active_subsystem;
	ops.get_subsystem_info = get_subsystem_info;
	ops.is_lib_initialized = is_lib_initialized;

	/* Key database management */
	ops.get_key_info = key_db_get_info;
	ops.add_key_info = key_db_add;
	ops.update_key_info = key_db_update;
	ops.delete_key_info = key_db_delete;

	status = smw_init(&ops);

	if (status == SMW_STATUS_OK) {
		status = get_default_config(&buffer, &size);

		if (status == SMW_STATUS_OK)
			status = smw_config_load(buffer, size, &offset);
	}

	if (buffer)
		free(buffer);

	if (status == SMW_STATUS_OK)
		osal_priv.lib_initialized = 1;

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
