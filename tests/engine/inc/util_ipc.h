/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_IPC_H__
#define __UTIL_IPC_H__

#include "util_app.h"

enum ipc_op_cmd { IPC_POST_SEM = 0 };

/**
 * struct ipc_op - Structure to send/receive IPC command
 * @cmd: Operation listed in the @ipc_op_cmd enumerate
 * @args: Operation arguments
 */
struct ipc_op {
	enum ipc_op_cmd cmd;

	union ipc_args {
		char name[256];
	} args;
};

/**
 * util_ipc_start() - Start the IPC thread
 * @app: Application data
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the arguments is not correct.
 * -INTERNAL_OUT_OF_MEMORY - Internal allocation error.
 * -FAILED                 - Thread creating failure.
 */
int util_ipc_start(struct app_data *app);

/**
 * util_ipc_end() - End the IPC thread
 * @app: Application data
 */
void util_ipc_end(struct app_data *app);

/**
 * util_ipc_send() - Send operation to given application name
 * @app: Active application data
 * @app_name: Application name destination
 * @op: IPC operation
 *
 * If @app_name is "all", the operation is broadcasted to all applications.
 *
 * Return:
 * PASSED  - Success
 * or any error code (see enum err_num)
 */
int util_ipc_send(struct app_data *app, const char *app_name,
		  struct ipc_op *op);

#endif /* __UTIL_IPC_H__ */
