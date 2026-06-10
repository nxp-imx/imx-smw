/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright 2026 NXP
 */

#ifndef __OSAL_ZEPHYR_INTERNAL_H__
#define __OSAL_ZEPHYR_INTERNAL_H__

#include <zephyr/logging/log.h>

#include "osal.h"

/*******************************************************************************
 * CACHE Handling Definitions
 ******************************************************************************/
#if defined(CACHE_MODE_WRITE_THROUGH) && (CACHE_MODE_WRITE_THROUGH > 0u)
#define DCACHE_INVALIDATE(addr, size)                                          \
	DCACHE_InvalidateByRange((uint32_t)(addr), (size))
#define DCACHE_CLEAN(addr, size) DCACHE_CleanByRange((uint32_t)(addr), (size))
/* Note: CACHE handling on ELE Crypto level work only with cache policy set to write-trough,
 *       because ELE doesn't own the buffers. If write-back is required,
 *       user needs to handle it on system/application level.
 */
#include "fsl_cache.h"
#else /* !CACHE_MODE_WRITE_THROUGH */
#define DCACHE_INVALIDATE(addr, size)                                          \
	{                                                                      \
		(void)addr;                                                    \
		(void)size;                                                    \
	}
#define DCACHE_CLEAN(addr, size)                                               \
	{                                                                      \
		(void)addr;                                                    \
		(void)size;                                                    \
	}

#endif /* CACHE_MODE_WRITE_THROUGH */

#define TRACE_FUNCTION_CALL LOG_DBG("Executing %s\n", __func__)

/* Debug levels */
#define DBG_LEVEL_NONE	  0 /* No trace */
#define DBG_LEVEL_ERROR	  1 /* Failures of which the user must be aware */
#define DBG_LEVEL_INFO	  2 /* Traces which could interest the user */
#define DBG_LEVEL_DEBUG	  3 /* First level of debugging information */
#define DBG_LEVEL_VERBOSE 4 /* Second level of debugging information */
#define DBG_LEVEL_EXTRA	  5 /* Maximum level of debugging information */

/*
 * Define the configuration flags ids
 */
#define CONFIG_SMW_CONFIG_FILE BIT(0)
#define CONFIG_SMW_DATABASE    BIT(1)
#define CONFIG_TEE	       BIT(2)
#define CONFIG_SECO	       BIT(3)
#define CONFIG_ELE	       BIT(4)

/**
 * struct smw_info - SMW library configuration
 * @smw_config_file: SMW configuration file
 * @smw_database: SMW database file
 */
struct smw_info {
	char *smw_config_file;
	char *smw_database;
};

/**
 * struct lib_config_args - Library configuration arguments
 * @config_flags: Flags the library configuration set
 * @smw_info: SMW library configuration
 * @tee_info: TEE subsystem configuration
 * @se_seco_info: Secure Enclave SECO subsystem configuration
 * @se_ele_info: Secure Enclave ELE subsystem configuration
 */
struct lib_config_args {
	unsigned int config_flags;
	struct smw_info smw_info;
	struct se_info se_ele_info;
};

struct osal_ctx {
	int lib_initialized;
	struct lib_config_args config;
	smw_subsystem_t active_subsystem_name;
	struct k_heap heap;
	void *heap_buf;
	size_t heap_size;
};

/**
 * get_osal_ctx() - Get the OSAL context
 *
 * Return:
 * Pointer to the OSAL context
 */
struct osal_ctx *get_osal_ctx(void);

/* Mutex operations */
int osal_zephyr_mutex_init(void **mutex);
int osal_zephyr_mutex_destroy(void **mutex);
int osal_zephyr_mutex_lock(void *mutex);
int osal_zephyr_mutex_unlock(void *mutex);

/* Thread operations */
int osal_zephyr_thread_create(unsigned long *thread,
			      void *(*start_routine)(void *), void *arg);
int osal_zephyr_thread_cancel(unsigned long thread);

/* Configuration operations */
int osal_zephyr_get_subsystem_info(smw_subsystem_t subsystem_name, void *info);

/* Database operations */
int osal_zephyr_get_obj_info(struct smw_osal_object *descriptor);
int osal_zephyr_add_obj_info(struct smw_osal_object *descriptor);
int osal_zephyr_update_obj_info(struct smw_osal_object *descriptor);
int osal_zephyr_delete_obj_info(struct smw_osal_object *descriptor);
int osal_zephyr_find_obj_init(void **find_ctx,
			      struct smw_osal_object *descriptor);
int osal_zephyr_find_obj_next(void *find_ctx,
			      struct smw_osal_object *descriptor);
int osal_zephyr_find_obj_final(void *find_ctx);

/* File operations */
int osal_zephyr_file_write(uint32_t blob_id_msb, uint32_t blob_id_lsb,
			   uint32_t blob_ext, uint32_t *chunk, size_t chunk_sz);
int osal_zephyr_file_read(uint32_t blob_id_msb, uint32_t blob_id_lsb,
			  uint32_t blob_id_ext, uint32_t *chunk, size_t *sz);
int osal_zephyr_file_initialize(void);

/* Cache operations */
void osal_zephyr_dcache_invalidate(void *addr, size_t size);
void osal_zephyr_dcache_clean(void *addr, size_t size);

/* Shared memory operations */
void osal_shared_memory_init(void);
void osal_shared_memory_deinit(void);
void *osal_shared_memory_alloc(void *buf, size_t size, uintptr_t *phys_addr);
void osal_shared_memory_free(void *buf, size_t size, void *original_buf);

void *osal_get_mu_base(void);

#endif /* __OSAL_ZEPHYR_INTERNAL_H__ */
