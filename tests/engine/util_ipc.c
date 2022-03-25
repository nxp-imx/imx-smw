// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <mqueue.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>

#include "util.h"
#include "util_debug.h"
#include "util_ipc.h"
#include "util_list.h"
#include "util_sem.h"

#define QUEUE_MODE_ACCESS 0600

struct ipc_data {
	mqd_t queue;
	pthread_t thr_id;
};

static void *process_ipc(void *arg)
{
	ssize_t rsize;
	size_t exp_size;
	unsigned int priority;
	struct app_data *app = arg;
	struct ipc_op op = { 0 };

	if (!app || !app->ipc || !app->ipc->queue)
		exit(ERR_CODE(BAD_ARGS));

	/*
	 * Create the application IPC queue
	 */

	exp_size = sizeof(op);

	do {
		rsize = mq_receive(app->ipc->queue, (char *)&op, exp_size,
				   &priority);
		if (rsize == -1) {
			DBG_PRINT("IPC Message receive %s", util_get_strerr());
			continue;
		}
		if ((size_t)rsize < exp_size) {
			DBG_PRINT("IPC Message received size %d expected %d",
				  rsize, exp_size);
			continue;
		}

		switch (op.cmd) {
		case IPC_POST_SEM:
			util_sem_ipc_post(app, op.args.name);
			break;

		default:
			DBG_PRINT("Unknown IPC command %d", op.cmd);
			break;
		}
	} while (1);

	exit(ERR_CODE(FAILED));
	return NULL;
}

static char *get_ipc_queue_name(struct app_data *app)
{
	char *q_name = NULL;

	if (!app || !strlen(app->name) || !app->id) {
		DBG_PRINT_BAD_ARGS();
		return q_name;
	}

	/* Share file name is a null-terminated string starting with '/' */
	q_name = calloc(1, strlen(app->name) + sizeof(app->id) + 2);
	if (q_name) {
		if (sprintf(q_name, "/%s.%d", app->name, app->id) < 0) {
			free(q_name);
			q_name = NULL;
		}
	}

	return q_name;
}

/**
 * ipc_queue_create_open() - Create/Open an application IPC message queue
 * @app: Application data
 * @queue_desc: Queue descriptor created/opened
 * @fcreate: 1 if queue creation
 *
 * The queue is created if not exist else it's opened.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure
 */
static int ipc_queue_create_open(struct app_data *app, mqd_t *queue_desc,
				 int fcreate)
{
	int ret = ERR_CODE(FAILED);
	struct mq_attr attr = { 0 };
	char *q_name = NULL;
	mqd_t queue;
	int oflags = O_WRONLY;

	if (!app) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	q_name = get_ipc_queue_name(app);
	if (!q_name) {
		DBG_PRINT("Unable to create %s queue name", app->name);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	attr.mq_maxmsg = app->test->nb_apps;
	attr.mq_msgsize = sizeof(struct ipc_op);

	if (fcreate) {
		oflags = O_RDWR | O_CREAT | O_EXCL;
		(void)mq_unlink(q_name);
	}

	DBG_PRINT("Create %s queue name %s", app->name, q_name);
	queue = mq_open(q_name, oflags, QUEUE_MODE_ACCESS, &attr);
	if (queue == (mqd_t)-1) {
		DBG_PRINT("Create %s queue name %s %s", app->name, q_name,
			  util_get_strerr());
		goto end;
	}

	if (mq_getattr(queue, &attr) == -1) {
		DBG_PRINT("%s get queue attribute of %s %s", app->name, q_name,
			  util_get_strerr());
		(void)mq_unlink(q_name);
		goto end;
	}

	DBG_PRINT("%s queue %s: Maximum # of messages on queue: %ld\n",
		  app->name, q_name, attr.mq_maxmsg);
	DBG_PRINT("%s queue %s: Maximum message size:           %ld\n",
		  app->name, q_name, attr.mq_msgsize);

	ret = ERR_CODE(PASSED);

	*queue_desc = queue;

end:
	free(q_name);

	return ret;
}

/**
 * ipc_queue_create() - Create an application IPC message queue
 * @app: Application data
 *
 * The queue is created if not exist else it's opened.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure
 */
static int ipc_queue_create(struct app_data *app)
{
	if (!app || !app->ipc) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	return ipc_queue_create_open(app, &app->ipc->queue, 1);
}

/**
 * ipc_queue_open() - Open an application IPC message queue
 * @app: Application data
 * @queue: Queue descriptor opened
 *
 * The queue is created if not exist else it's opened.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure
 */
static int ipc_queue_open(struct app_data *app, mqd_t *queue)
{
	if (!app || !queue) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	return ipc_queue_create_open(app, queue, 0);
}

/**
 * ipc_queue_destroy() - Destroy application IPC Queue message
 * @app: Application data
 */
static void ipc_queue_destroy(struct app_data *app)
{
	char *q_name = NULL;

	if (!app || !app->ipc) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	if (!app->ipc->queue)
		return;

	q_name = get_ipc_queue_name(app);
	if (!q_name) {
		DBG_PRINT("Unable to create %s queue name", app->name);
		return;
	}

	(void)mq_unlink(q_name);

	app->ipc->queue = 0;

	free(q_name);
}

/**
 * ipc_queue_post() - Post an message to given application
 * @to: Application data of the semaphore to post
 * @op: Operation
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure
 */
static int ipc_queue_post(struct app_data *to, struct ipc_op *op)
{
	int res;
	mqd_t queue;

	res = ipc_queue_open(to, &queue);
	if (res != ERR_CODE(PASSED))
		return res;

	if (mq_send(queue, (const char *)op, sizeof(*op), 0)) {
		DBG_PRINT("Send message to %s %s", to->name, util_get_strerr());
		res = ERR_CODE(FAILED);
	}

	if (mq_close(queue)) {
		DBG_PRINT("Close %s queue %s", to->name, util_get_strerr());
		res = ERR_CODE(FAILED);
	}

	return res;
}

int util_ipc_start(struct app_data *app)
{
	int res;

	if (!app)
		return ERR_CODE(BAD_ARGS);

	app->ipc = calloc(1, sizeof(*app->ipc));
	if (!app->ipc) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	res = ipc_queue_create(app);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (pthread_create(&app->ipc->thr_id, NULL, &process_ipc, app)) {
		DBG_PRINT("Thread creation %s", util_get_strerr());
		res = ERR_CODE(FAILED);
	} else {
		res = ERR_CODE(PASSED);
	}

exit:
	return res;
}

void util_ipc_end(struct app_data *app)
{
	if (app && app->ipc) {
		if (app->ipc->thr_id && pthread_cancel(app->ipc->thr_id))
			DBG_PRINT("Cancel Thread error: %s", util_get_strerr());

		ipc_queue_destroy(app);

		free(app->ipc);
	}
}

int util_ipc_send(struct app_data *app, const char *app_name, struct ipc_op *op)
{
	int status = ERR_CODE(PASSED);
	int res;
	int fbroadcast = 0;
	int nb_apps = 0;
	struct node *node = NULL;
	struct app_data *to = NULL;

	if (!app || !app->test || !app->test->apps || !app_name || !op) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (!strcmp(app_name, "all"))
		fbroadcast = 1;

	while ((node = util_list_next(app->test->apps, node, NULL))) {
		to = util_list_data(node);
		if (to && !strcmp(to->name, app_name))
			return ipc_queue_post(to, op);

		if (to) {
			if (!fbroadcast && strcmp(to->name, app_name))
				continue;

			nb_apps++;
			res = ipc_queue_post(to, op);
			status = (status == ERR_CODE(PASSED)) ? res : status;
		}
	};

	DBG_PRINT("%s not created", app_name);
	if (!nb_apps)
		status = ERR_CODE(FAILED);

	return status;
}
