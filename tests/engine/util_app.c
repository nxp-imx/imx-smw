// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_app.h"
#include "util_cipher.h"
#include "util_context.h"
#include "util_key.h"
#include "util_list.h"
#include "util_mutex.h"
#include "util_sem.h"
#include "util_sign.h"
#include "util_thread.h"

static void util_app_destroy(void *data)
{
	struct app_data *app_data = data;
	int err;

	if (!app_data)
		return;

	err = util_list_clear(app_data->key_identifiers);
	if (err != ERR_CODE(PASSED))
		DBG_PRINT("Clear list key identifiers error %d", err);

	err = util_list_clear(app_data->op_contexts);
	if (err != ERR_CODE(PASSED))
		DBG_PRINT("Clear list operation contexts error %d", err);

	err = util_list_clear(app_data->ciphers);
	if (err != ERR_CODE(PASSED))
		DBG_PRINT("Clear list ciphers error %d", err);

	err = util_list_clear(app_data->signatures);
	if (err != ERR_CODE(PASSED))
		DBG_PRINT("Clear list signatures error %d", err);

	err = util_list_clear(app_data->threads);
	if (err != ERR_CODE(PASSED))
		DBG_PRINT("Clear list threads error %d", err);

	err = util_list_clear(app_data->semaphores);
	if (err != ERR_CODE(PASSED))
		DBG_PRINT("Clear list semaphores error %d", err);

	/* Destroy the thread completion mutex and condition */
	err = util_thread_ends_destroy(app_data);
	if (err != ERR_CODE(PASSED))
		DBG_PRINT("Application Thread ends destroy error %d", err);

	if (app_data->definition)
		json_object_put(app_data->definition);

	free(app_data);
}

int util_app_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, util_app_destroy);
}

int util_app_register(struct test_data *test, unsigned int id,
		      struct app_data **data)
{
	int err;
	struct app_data *app_data = NULL;

	if (!test || !test->apps || !id || !data) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	app_data = calloc(1, sizeof(*app_data));
	if (!app_data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	(void)sprintf(app_data->name, "App %d", id);
	app_data->test = test;

	err = util_key_init(&app_data->key_identifiers);
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

	err = util_thread_init(&app_data->threads);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_sem_init(&app_data->semaphores);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_list_add_node(test->apps, id, app_data);
	if (err != ERR_CODE(PASSED))
		goto exit;

	*data = app_data;

exit:
	if (err != ERR_CODE(PASSED))
		util_app_destroy(app_data);

	return err;
}

struct app_data *util_app_get_active_data(void)
{
	pid_t pid = getpid();
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
