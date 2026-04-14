// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <zephyr/kernel.h>

#include <stdarg.h>
#include <stdio.h>

#include "fsl_common.h"

#include "osal.h"
#include "internal.h"
#include "smw_config.h"
#include "smw_osal.h"
#include "smw/names.h"

LOG_MODULE_REGISTER(smw_osal, CONFIG_SMW_LOG_LEVEL);

static struct osal_ctx *osal_ctx;

/* Critical section using IRQ lock */
static unsigned int irq_lock_key;

static void critical_section_start(void)
{
	irq_lock_key = irq_lock();
}

static void critical_section_stop(void)
{
	irq_unlock(irq_lock_key);
}

/* Debug print functions */
static void vprint(unsigned int level, const char *format, va_list arg)
{
	char *buffer = NULL;

	vasprintf(&buffer, format, arg);

	if (!buffer)
		return;

	switch (level) {
	case DBG_LEVEL_ERROR:
		LOG_ERR("%s", buffer);
		break;

	/*
	 * LOG_LEVEL_INF value (3) is used for both DBG_LEVEL_INFO and DBG_LEVEL_DEBUG
	 * https://docs.zephyrproject.org/latest/doxygen/html/log__core_8h.html#a281bc2ce5315e6fae369796c0fdf5c1d
	 */
	case DBG_LEVEL_INFO:
	case DBG_LEVEL_DEBUG:
		LOG_INF("%s", buffer);
		break;

	/*
	 * LOG_LEVEL_DBG value (4) is used for both DBG_LEVEL_VERBOSE and DBG_LEVEL_EXTRA
	 * https://docs.zephyrproject.org/latest/doxygen/html/log__core_8h.html#ad1f7d41b1af28ba81ea63d24c9b690cc
	 */
	case DBG_LEVEL_VERBOSE:
	case DBG_LEVEL_EXTRA:
		LOG_DBG("%s", buffer);
		break;

	default:
		break;
	}

	free(buffer);
}

static void hex_dump(unsigned int level, const unsigned char *addr,
		     unsigned int size, unsigned int align)
{
	(void)level;
	(void)align;

	LOG_HEXDUMP_DBG(addr, size, "SMW:");
}

static void register_active_subsystem(smw_subsystem_t subsystem_name)
{
	LOG_INF("Active subsystem: %d", subsystem_name);
}

inline struct osal_ctx *get_osal_ctx(void)
{
	return osal_ctx;
}

static bool is_lib_initialized(void)
{
	return osal_ctx ? osal_ctx->lib_initialized : false;
}

static int set_ele_info(void *info, size_t info_size)
{
	if (!osal_ctx)
		return SMW_STATUS_ALLOC_FAILURE;

	if (info_size != sizeof(struct se_info))
		return SMW_STATUS_INVALID_PARAM;

	osal_ctx->config.se_ele_info = *((struct se_info *)info);
	osal_ctx->config.config_flags |= CONFIG_ELE;

	return SMW_STATUS_OK;
}

enum smw_status_code smw_osal_set_subsystem_info(smw_subsystem_t subsystem_name,
						 void *info, size_t info_size)
{
	enum smw_status_code status = SMW_STATUS_OK;

	TRACE_FUNCTION_CALL;

	if (!info || subsystem_name >= SMW_SUBSYSTEM_NAME_NB)
		return SMW_STATUS_INVALID_PARAM;

	if (subsystem_name == SMW_SUBSYSTEM_NAME_ELE)
		status = set_ele_info(info, info_size);
	else
		status = SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME;

	return status;
}

enum smw_status_code smw_osal_open_obj_db(const char *file,
					  size_t len __maybe_unused)
{
	enum smw_status_code status = SMW_STATUS_OK;

	TRACE_FUNCTION_CALL;

	if (!osal_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	if (osal_ctx->lib_initialized) {
		LOG_INF("Library is already initialized\n");
		status = SMW_STATUS_LIBRARY_ALREADY_INIT;
		goto end;
	}

end:
	return status;
}

__weak int osal_zephyr_file_initialize(void)
{
	return -1;
}

__weak int osal_zephyr_file_write(uint32_t blob_id_msb, uint32_t blob_id_lsb,
				  uint32_t blob_ext, uint32_t *chunk,
				  size_t chunk_sz)
{
	(void)blob_id_msb;
	(void)blob_id_lsb;
	(void)blob_ext;
	(void)chunk;
	(void)chunk_sz;

	return -1;
}

__weak int osal_zephyr_file_read(uint32_t blob_id_msb, uint32_t blob_id_lsb,
				 uint32_t blob_id_ext, uint32_t *chunk,
				 size_t *sz)
{
	(void)blob_id_msb;
	(void)blob_id_lsb;
	(void)blob_id_ext;
	(void)chunk;
	(void)sz;

	return -1;
}

void osal_zephyr_dcache_invalidate(void *addr, size_t size)
{
	DCACHE_INVALIDATE(addr, size);
}

void osal_zephyr_dcache_clean(void *addr, size_t size)
{
	DCACHE_CLEAN(addr, size);
}

__weak void osal_shared_memory_init(void)
{
	/* Default implementation does nothing, as shared memory is useless for non-MMU systems */
}

__weak void osal_shared_memory_deinit(void)
{
	/* Default implementation does nothing, as shared memory is useless for non-MMU systems */
}

__weak void *osal_shared_memory_alloc(void *buf, size_t size,
				      uintptr_t *phys_addr)
{
	(void)size;

	*phys_addr = (uintptr_t)buf;

	return buf;
}

__weak void osal_shared_memory_free(void *buf, size_t size, void *original_buf)
{
	(void)buf;
	(void)size;
}

__weak void *osal_get_mu_base(void)
{
	return (void *)MU_RT__S3MUA_BASE;
}

enum smw_status_code smw_osal_lib_init(void)
{
	enum smw_status_code status = SMW_STATUS_OK;
	/* OSAL operations structure */
	static const struct smw_ops zephyr_ops = {
		.critical_section_start = critical_section_start,
		.critical_section_stop = critical_section_stop,
		.mutex_init = osal_zephyr_mutex_init,
		.mutex_destroy = osal_zephyr_mutex_destroy,
		.mutex_lock = osal_zephyr_mutex_lock,
		.mutex_unlock = osal_zephyr_mutex_unlock,
		.thread_create = osal_zephyr_thread_create,
		.thread_cancel = osal_zephyr_thread_cancel,
		.vprint = vprint,
		.hex_dump = hex_dump,
		.register_active_subsystem = register_active_subsystem,
		.get_subsystem_info = osal_zephyr_get_subsystem_info,
		.is_lib_initialized = is_lib_initialized,
		.get_obj_info = osal_zephyr_get_obj_info,
		.add_obj_info = osal_zephyr_add_obj_info,
		.update_obj_info = osal_zephyr_update_obj_info,
		.delete_obj_info = osal_zephyr_delete_obj_info,
		.find_obj_init = osal_zephyr_find_obj_init,
		.find_obj_next = osal_zephyr_find_obj_next,
		.find_obj_final = osal_zephyr_find_obj_final,
		.file_initialize = osal_zephyr_file_initialize,
		.file_write = osal_zephyr_file_write,
		.file_read = osal_zephyr_file_read,
		.dcache_invalidate = osal_zephyr_dcache_invalidate,
		.dcache_clean = osal_zephyr_dcache_clean,
		.shared_memory_init = osal_shared_memory_init,
		.shared_memory_deinit = osal_shared_memory_deinit,
		.shared_memory_alloc = osal_shared_memory_alloc,
		.shared_memory_free = osal_shared_memory_free,
		.get_mu_base = osal_get_mu_base,
	};
	static struct se_info default_ele_info = {
		.storage_id = 0x50534154,  /* PSAT */
		.storage_nonce = 0x444546, /* DEF */
		.storage_replay = 1000,
		.storage_shared = false
	};

	TRACE_FUNCTION_CALL;

	osal_ctx = calloc(1, sizeof(struct osal_ctx));
	if (!osal_ctx) {
		LOG_DBG("OSAL context allocation failed\n");
		return SMW_STATUS_ALLOC_FAILURE;
	}

	status = set_ele_info(&default_ele_info, sizeof(default_ele_info));
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_init(&zephyr_ops);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_load(NULL, 0, NULL);
	if (status == SMW_STATUS_OK)
		osal_ctx->lib_initialized = 1;

end:
	LOG_DBG("%s returned %d\n", __func__, status);
	return status;
}
