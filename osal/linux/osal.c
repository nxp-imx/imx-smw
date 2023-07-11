// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#include "local.h"

#include "smw_config.h"
#include "smw_osal.h"

__attribute__((destructor)) static void destructor(void);

static struct osal_ctx *osal_ctx;

inline struct osal_ctx *get_osal_ctx(void)
{
	return osal_ctx;
}

static inline int alloc_context(void)
{
	if (!osal_ctx) {
		DBG_PRINTF(DEBUG, "OSAL context allocation\n");
		osal_ctx = calloc(1, sizeof(struct osal_ctx));
		if (!osal_ctx) {
			DBG_PRINTF(DEBUG, "OSAL context allocation failed\n");
			return SMW_STATUS_ALLOC_FAILURE;
		}
	}

	return SMW_STATUS_OK;
}

static inline void free_context(void)
{
	free(osal_ctx);
	osal_ctx = NULL;
}

int mutex_init(void **mutex)
{
	TRACE_FUNCTION_CALL;

	if (!mutex)
		return -1;

	if (*mutex)
		return -1;

	*mutex = malloc(sizeof(pthread_mutex_t));
	if (!*mutex)
		return -1;

	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	return pthread_mutex_init((pthread_mutex_t *)*mutex, NULL);
}

int mutex_destroy(void **mutex)
{
	TRACE_FUNCTION_CALL;

	if (!mutex)
		return -1;

	if (!*mutex)
		return -1;

	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	if (pthread_mutex_destroy((pthread_mutex_t *)*mutex))
		return -1;

	free(*mutex);
	*mutex = NULL;

	return 0;
}

int mutex_lock(void *mutex)
{
	TRACE_FUNCTION_CALL;

	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	return pthread_mutex_lock((pthread_mutex_t *)mutex);
}

int mutex_unlock(void *mutex)
{
	TRACE_FUNCTION_CALL;

	DBG_PRINTF(DEBUG, "%s: %p\n", __func__, mutex);

	return pthread_mutex_unlock((pthread_mutex_t *)mutex);
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

static void vprint(const char *format, va_list arg)
{
	printf("(%d) [0x%lx] ", getpid(), pthread_self());

	vprintf(format, arg);

	(void)fflush(stdout);
}

static int fill_dbg_buffer(char *out, size_t size, unsigned int *off,
			   const char *fmt, size_t fmt_size, char c)
{
	int ret = -1;

	if (*off >= size)
		return ret;

	if (fmt_size >= size)
		printf(fmt, c);

	if (fmt_size >= size - *off) {
		printf("%.*s", *off, out);
		*off = 0;
	}

	ret = snprintf(out + *off, size - *off, fmt, c);
	if (ret >= 0 && ret <= (int)fmt_size) {
		*off += ret;
		ret = 0;
	}

	return ret;
}

static void hex_dump(const unsigned char *addr, unsigned int size,
		     unsigned int align)
{
	unsigned int i = 0;
	/* Size of out must be at least equal to 3. */
	char out[256] = { 0 };
	unsigned int off = 0;
	unsigned int align_mask = 0;

	printf("(%d) [0x%lx] (%p-%u)\n", getpid(), pthread_self(), addr, size);

	if (!addr) {
		printf("Buffer address is NULL\n");
		return;
	}

	if (align > 4)
		align_mask = BIT(4);
	else if (align)
		align_mask = BIT(align) & 0xF;

	if (align_mask)
		align_mask -= 1;

	for (i = 0; i < size; i++) {
		if (fill_dbg_buffer(out, sizeof(out), &off, "%.2x ", 3,
				    addr[i]))
			break;

		if (!((i + 1) & align_mask)) {
			if (fill_dbg_buffer(out, sizeof(out), &off, "%c", 1,
					    '\n'))
				break;
		}
	}
	printf("%.*s\n", off, out);

	(void)fflush(stdout);
}

static void register_active_subsystem(const char *subsystem_name)
{
	struct osal_ctx *ctx = get_osal_ctx();

	TRACE_FUNCTION_CALL;

	if (ctx)
		ctx->active_subsystem_name = subsystem_name;
}

static int set_tee_info(void *info, size_t info_size)
{
	struct osal_ctx *ctx = get_osal_ctx();

	if (!ctx)
		return SMW_STATUS_ALLOC_FAILURE;

	if (info_size != sizeof(struct tee_info))
		return SMW_STATUS_INVALID_PARAM;

	ctx->config.tee_info = *((struct tee_info *)info);
	ctx->config.config_flags |= CONFIG_TEE;

	return SMW_STATUS_OK;
}

static int get_tee_info(struct tee_info *info)
{
	int ret = -1;

	struct osal_ctx *ctx = get_osal_ctx();

	/*
	 * Copy the TEE configuration if value set
	 * in the library instance
	 */
	if (ctx && ctx->config.config_flags & CONFIG_TEE) {
		*info = ctx->config.tee_info;
		ret = 0;
	}

	return ret;
}

static int set_hsm_info(void *info, size_t info_size)
{
	struct osal_ctx *ctx = get_osal_ctx();

	if (!ctx)
		return SMW_STATUS_ALLOC_FAILURE;

	if (info_size != sizeof(struct se_info))
		return SMW_STATUS_INVALID_PARAM;

	ctx->config.se_hsm_info = *((struct se_info *)info);
	ctx->config.config_flags |= CONFIG_HSM;

	return SMW_STATUS_OK;
}

static int get_hsm_info(struct se_info *info)
{
	int ret = -1;

	struct osal_ctx *ctx = get_osal_ctx();

	/*
	 * Copy the Storage Nonce configuration if value set
	 * in the library instance
	 */
	if (ctx && ctx->config.config_flags & CONFIG_HSM) {
		*info = ctx->config.se_hsm_info;
		ret = 0;
	}

	return ret;
}

static int set_ele_info(void *info, size_t info_size)
{
	struct osal_ctx *ctx = get_osal_ctx();

	if (!ctx)
		return SMW_STATUS_ALLOC_FAILURE;

	if (info_size != sizeof(struct se_info))
		return SMW_STATUS_INVALID_PARAM;

	ctx->config.se_ele_info = *((struct se_info *)info);
	ctx->config.config_flags |= CONFIG_ELE;

	return SMW_STATUS_OK;
}

static int get_ele_info(struct se_info *info)
{
	int ret = -1;

	struct osal_ctx *ctx = get_osal_ctx();

	/*
	 * Copy the Storage Nonce configuration if value set
	 * in the library instance
	 */
	if (ctx && ctx->config.config_flags & CONFIG_ELE) {
		*info = ctx->config.se_ele_info;
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

	if (!strcmp(subsystem_name, "ELE"))
		return get_ele_info(info);

	DBG_PRINTF(VERBOSE, "%s unknown %s subsystem\n", __func__,
		   subsystem_name);

	return -1;
}

static bool is_lib_initialized(void)
{
	struct osal_ctx *ctx = get_osal_ctx();

	return ctx ? ctx->lib_initialized : false;
}

static int get_default_config(char **buffer, unsigned int *size)
{
	int status = SMW_STATUS_NO_CONFIG_LOADED;
	long fsize = 0;

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

static void stop(void)
{
	int __maybe_unused status = 0;

	TRACE_FUNCTION_CALL;

	if (osal_ctx) {
		status = smw_config_unload();
		DBG_PRINTF(VERBOSE, "Unload configuration status: %d\n",
			   status);

		status = smw_deinit();
		DBG_PRINTF(VERBOSE, "SMW deinit status: %d\n", status);

		key_db_close();

		free_context();
	}
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
	enum smw_status_code status = SMW_STATUS_OK;

	TRACE_FUNCTION_CALL;

	status = alloc_context();
	if (status != SMW_STATUS_OK)
		return status;

	if (!subsystem || !info)
		return SMW_STATUS_INVALID_PARAM;

	status = smw_config_subsystem_loaded(subsystem);
	if (status != SMW_STATUS_SUBSYSTEM_LOADED) {
		if (!strcmp(subsystem, "TEE"))
			status = set_tee_info(info, info_size);
		else if (!strcmp(subsystem, "HSM"))
			status = set_hsm_info(info, info_size);
		else if (!strcmp(subsystem, "ELE"))
			status = set_ele_info(info, info_size);
		else
			status = SMW_STATUS_UNKNOWN_NAME;
	}

	return status;
}

__export enum smw_status_code smw_osal_open_key_db(const char *file,
						   size_t len __maybe_unused)
{
	enum smw_status_code status = SMW_STATUS_OK;

	TRACE_FUNCTION_CALL;

	DBG_PRINTF(INFO, "Open Key database %s (%zu)\n", file, len);

	status = alloc_context();
	if (status != SMW_STATUS_OK)
		return status;

	if (key_db_open(file)) {
		DBG_PRINTF(ERROR, "Error opening/creating key db %s\n", file);
		return SMW_STATUS_KEY_DB_INIT;
	}

	return SMW_STATUS_OK;
}

__export enum smw_status_code smw_osal_lib_init(void)
{
	enum smw_status_code status = SMW_STATUS_OK;

	struct osal_ctx *ctx = NULL;
	struct smw_ops ops = { 0 };
	char *buffer = NULL;
	unsigned int size = 0;
	unsigned int offset = 0;

	TRACE_FUNCTION_CALL;

	status = alloc_context();
	if (status != SMW_STATUS_OK)
		goto end;

	ctx = get_osal_ctx();
	if (!ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	if (ctx->lib_initialized)
		return SMW_STATUS_LIBRARY_ALREADY_INIT;

	ops.mutex_init = mutex_init;
	ops.mutex_destroy = mutex_destroy;
	ops.mutex_lock = mutex_lock;
	ops.mutex_unlock = mutex_unlock;
	ops.thread_create = thread_create;
	ops.thread_cancel = thread_cancel;
	ops.vprint = vprint;
	ops.hex_dump = hex_dump;
	ops.register_active_subsystem = register_active_subsystem;
	ops.get_subsystem_info = get_subsystem_info;
	ops.is_lib_initialized = is_lib_initialized;

	/* Key database management */
	ops.get_key_info = key_db_get_info;
	ops.add_key_info = key_db_add;
	ops.update_key_info = key_db_update;
	ops.delete_key_info = key_db_delete;

	status = smw_init(&ops);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_default_config(&buffer, &size);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_load(buffer, size, &offset);

end:
	if (buffer)
		free(buffer);

	if (status == SMW_STATUS_OK)
		ctx->lib_initialized = 1;

	DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
