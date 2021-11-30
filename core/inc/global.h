/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include "osal.h"

/* SMW globals */
/**
 * struct smw_ctx - SMW context
 * @ops: Structure containing the OSAL primitives
 * @start_count: Number of threads/applications that started the SMW library
 *
 */
struct smw_ctx {
	struct smw_ops ops;
	int start_count;
};

extern struct smw_ctx g_smw_ctx;

#endif /* __GLOBAL_H__ */
