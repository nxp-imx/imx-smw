// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdlib.h>
#include <sys/wait.h>

#include "util.h"
#include "util_app.h"
#include "util_certificate.h"
#include "util_cipher.h"
#include "util_context.h"
#include "util_key.h"
#include "util_list.h"
#include "util_mac.h"
#include "util_sem.h"
#include "util_sign.h"
#include "util_thread.h"
#include "run_app.h"

static struct app_data *util_app_get_data(pid_t pid)
{
	struct test_data *test = util_get_test();
	struct app_data *data = NULL;
	struct node *node = NULL;

	if (!test)
		return NULL;

	do {
		data = NULL;
		node = util_list_next(test->apps, node, NULL);
		if (node)
			data = util_list_data(node);

		if (data && data->pid == pid)
			break;
	} while (node);

	return data;
}

static void util_app_destroy(void *data)
{
	struct app_data *app_data = data;
	int err = ERR_CODE(PASSED);

	if (!app_data)
		return;

	err = util_list_clear(app_data->keys);
	DBG_ASSERT(err == ERR_CODE(PASSED), "Clear list keys error %d", err);

	err = util_list_clear(app_data->op_contexts);
	DBG_ASSERT(err == ERR_CODE(PASSED),
		   "Clear list operation contexts error %d", err);

	err = util_list_clear(app_data->ciphers);
	DBG_ASSERT(err == ERR_CODE(PASSED), "Clear list ciphers error %d", err);

	err = util_list_clear(app_data->signatures);
	DBG_ASSERT(err == ERR_CODE(PASSED), "Clear list signatures error %d",
		   err);

	err = util_list_clear(app_data->macs);
	DBG_ASSERT(err == ERR_CODE(PASSED), "Clear list MACs error %d", err);

	err = util_list_clear(app_data->certificates);
	DBG_ASSERT(err == ERR_CODE(PASSED), "Clear list certificates error %d",
		   err);

	err = util_list_clear(app_data->threads);
	DBG_ASSERT(err == ERR_CODE(PASSED), "Clear list threads error %d", err);

	err = util_list_clear(app_data->semaphores);
	DBG_ASSERT(err == ERR_CODE(PASSED), "Clear list semaphores error %d",
		   err);

	/* Destroy the thread completion mutex and condition */
	err = util_thread_ends_destroy(app_data);
	DBG_ASSERT(err == ERR_CODE(PASSED),
		   "Application Thread ends destroy error %d", err);

	if (app_data->parent_def)
		json_object_put(app_data->parent_def);

	free(app_data);
}

/**
 * register_app() - Register an application
 * @test: Overall test global data object
 * @id: Application identifier
 * @data: Application data object allocated
 *
 * Allocate and initialize the application data.
 * Register the application in the test @apps list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
static int app_register(struct test_data *test, unsigned int id,
			struct app_data **data)
{
	int err = ERR_CODE(BAD_ARGS);
	struct app_data *app_data = NULL;

	if (!test || !test->apps || !id || !data) {
		DBG_PRINT_BAD_ARGS();
		return err;
	}

	app_data = calloc(1, sizeof(*app_data));
	if (!app_data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	app_data->id = id;
	(void)sprintf(app_data->name, "App %d", id);
	app_data->test = test;

	err = util_key_init(&app_data->keys);
	if (err != ERR_CODE(PASSED))
		goto exit;

	/* Build the keys list */
	err = util_key_build_keys_list(test->dir_def_file, test->definition,
				       app_data->keys);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_context_init(&app_data->op_contexts);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_cipher_init(&app_data->ciphers);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_sign_init(&app_data->signatures);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_mac_init(&app_data->macs);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_certificate_init(&app_data->certificates);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_thread_init(&app_data->threads);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_sem_init(&app_data->semaphores);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_list_add_node(test->apps, id, app_data);
	if (err == ERR_CODE(PASSED))
		*data = app_data;

exit:
	if (err != ERR_CODE(PASSED))
		// coverity[leaked_storage]
		util_app_destroy(app_data);

	return err;
}

int util_app_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, util_app_destroy, LIST_ID_TYPE_UINT);
}

struct app_data *util_app_get_active_data(void)
{
	pid_t pid = getpid();

	return util_app_get_data(pid);
}

int util_app_create(struct test_data *test, unsigned int app_id,
		    struct json_object *def)
{
	int res = ERR_CODE(BAD_ARGS);
	struct app_data *app = NULL;

	if (!test || !app_id) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = app_register(test, app_id, &app);
	if (res == ERR_CODE(PASSED))
		app->parent_def = json_object_get(def);

	return res;
}

int util_app_fork(struct app_data *app)
{
	int res = ERR_CODE(BAD_ARGS);
	int pid = 0;

	if (!app) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Flush all user-space buffered data before duplicating the process */
	(void)fflush(NULL);

	pid = fork();
	if (pid == -1) {
		DBG_PRINT("%s ==> fork() error :%s", app->name,
			  util_get_strerr());
		res = ERR_CODE(INTERNAL);
	} else if (pid) {
		/* This is the parent process */
		app->pid = pid;
		res = ERR_CODE(PASSED);
	} else {
		/* New child process */
		DBG_PRINT("Create new %s application %d", app->name, getpid());
		res = process_app(app);
		exit(res);
	}

	return res;
}

int util_app_wait(struct test_data *test)
{
	int res = ERR_CODE(PASSED);
	int wstatus = ERR_CODE(FAILED);
	struct node *node = NULL;
	struct app_data *app = NULL;

	if (!test || !test->apps) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	node = util_list_next(test->apps, node, NULL);
	while (node) {
		app = util_list_data(node);
		if (app) {
			DBG_PRINT("Wait %s (%d)", app->name, app->pid);
			waitpid(app->pid, &wstatus, 0);
			DBG_PRINT("Wait %s (%d) ret %s", app->name, app->pid,
				  util_get_err_code_str(wstatus));
			if (res == ERR_CODE(PASSED))
				res = wstatus;
		}

		node = util_list_next(test->apps, node, NULL);
	};

	return res;
}
