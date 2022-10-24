/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include "osal.h"

/**
 * struct smw_ctx - SMW context
 * @ops: Structure containing the OSAL primitives
 * @config_mutex: Read/write access mutex for the Configuration database
 * @start_count: Number of threads/applications that initialized the SMW library
 * @config_loaded: True if the configuration has been loaded already
 * @config_db: Configuration database
 *
 */
struct smw_ctx {
	struct smw_ops ops;
	void *config_mutex;
	int start_count;
	bool config_loaded;
	void *config_db;
};

/**
 * get_smw_ctx() - Get the SMW context
 *
 * Return:
 * Pointer to the SMW context
 */
struct smw_ctx *get_smw_ctx(void);

/**
 * get_smw_ops() - Get the SMW OSAL operations
 *
 * Return:
 * Pointer to the SMW OSAL operations
 */
struct smw_ops *get_smw_ops(void);

#endif /* __GLOBAL_H__ */
