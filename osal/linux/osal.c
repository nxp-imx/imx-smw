// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2021 NXP
 */

#include "osal.h"

__attribute__((constructor)) static void constructor(void);
__attribute__((destructor)) static void destructor(void);

const char *active_subsystem_name;

static int mutex_init(void **mutex)
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

static int mutex_destroy(void **mutex)
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

static int mutex_lock(void *mutex)
{
	int status = -1;

	TRACE_FUNCTION_CALL;

	status = pthread_mutex_lock((pthread_mutex_t *)mutex);

	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int mutex_unlock(void *mutex)
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

	active_subsystem_name = subsystem_name;
}

static int get_default_config(char **buffer, unsigned int *size)
{
	int status = -1;
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

	status = 0;

end:
	if (f)
		if (fclose(f))
			perror("fclose()");

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int start(void)
{
	int status = 0;

	struct smw_ops ops;
	char *buffer = NULL;
	unsigned int size = 0;
	unsigned int offset = 0;

	TRACE_FUNCTION_CALL;

	memset(&ops, 0, sizeof(ops));
	ops.mutex_init = mutex_init;
	ops.mutex_destroy = mutex_destroy;
	ops.mutex_lock = mutex_lock;
	ops.mutex_unlock = mutex_unlock;
	ops.thread_create = thread_create;
	ops.thread_cancel = thread_cancel;
	ops.thread_self = thread_self;
	ops.register_active_subsystem = register_active_subsystem;

	status = smw_init(&ops);
	if (status)
		goto end;

	status = get_default_config(&buffer, &size);
	if (status)
		goto end;

	status = smw_config_load(buffer, size, &offset);

end:
	if (buffer)
		free(buffer);

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

end:
	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void constructor(void)
{
	start();
}

static void destructor(void)
{
	stop();
}

__export __weak const char *smw_read_latest_subsystem_name(void)
{
	return NULL;
}
