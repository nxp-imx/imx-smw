// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_list.h"
#include "util_thread.h"
#include "run_thread.h"

static struct thread_data *get_active_thread_data(struct app_data *app)
{
	struct node *node = NULL;
	struct thread_data *thr;
	pthread_t tid;

	if (!app)
		return NULL;

	tid = pthread_self();

	node = util_list_next(app->threads, node, NULL);
	while (node) {
		thr = util_list_data(node);

		if (thr && thr->id == tid)
			return thr;

		node = util_list_next(app->threads, node, NULL);
	};

	return NULL;
}

static void thr_free_data(void *data)
{
	struct thread_data *thr_data = data;

	if (!thr_data)
		return;

	if (thr_data->state == RUNNING || thr_data->state == WAITING)
		pthread_cancel(thr_data->id);

	free(thr_data);
}

static int get_thread_definition(struct json_object *def_obj,
				 struct thread_data *thr)
{
	int res;
	char *def_file = NULL;

	if (!def_obj || !thr)
		return ERR_CODE(BAD_ARGS);

	/*
	 * Check if the Thread is defined with a test definition file
	 * or a detailled subtests
	 */
	res = util_read_json_type(&def_file, FILEPATH_OBJ, t_string, def_obj);
	if (res == ERR_CODE(PASSED)) {
		/* Read the thread file definition */
		res = util_read_json_file(thr->app->dir_def_file, def_file,
					  &thr->def);
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		/*
		 * Increment reference to application test definition
		 * in order to align with the thread file definition
		 * and call json_object_put() regardless how thread
		 * test is defined.
		 */
		thr->def = json_object_get(def_obj);
		res = ERR_CODE(PASSED);
	}

	if (res != ERR_CODE(PASSED))
		DBG_PRINT("Error %d", res);

	return res;
}

static int read_thread_loop(struct json_object_iter *thr_obj, int *loop,
			    struct json_object **thr_def)
{
	json_object *otmp;

	if (json_object_array_length(thr_obj->val) != 2) {
		DBG_PRINT("\"%s\" is more than 2 array entries", thr_obj->key);
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	otmp = json_object_array_get_idx(thr_obj->val, 0);
	if (json_object_get_type(otmp) != json_type_int) {
		DBG_PRINT("\"%s\" first entry is not a json-c integer",
			  thr_obj->key);
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	*loop = json_object_get_int(otmp);

	otmp = json_object_array_get_idx(thr_obj->val, 1);
	if (json_object_get_type(otmp) != json_type_object) {
		DBG_PRINT("\"%s\" first entry is not a json-c object",
			  thr_obj->key);
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	*thr_def = otmp;

	return ERR_CODE(PASSED);
}

int util_thread_start(struct app_data *app, struct json_object_iter *thr_obj,
		      unsigned int thr_num)
{
	int err;
	int loop = 0;
	struct thread_data *thr = NULL;
	struct json_object *def_obj = NULL;

	if (!app || !thr_obj)
		return ERR_CODE(BAD_ARGS);

	DBG_PRINT("%s", thr_obj->key);

	/*
	 * Thread can be a defined with a JSON-C object or an array
	 * to run the thread x times.
	 * In case of thread loop, the Thread JSON-C format must be:
	 *       [x, {...}]
	 *    2 entries where first is a integer and second is a
	 *    an object.
	 */
	switch (json_object_get_type(thr_obj->val)) {
	case json_type_array:
		err = read_thread_loop(thr_obj, &loop, &def_obj);
		if (err != ERR_CODE(PASSED)) {
			FPRINT_MESSAGE(app->log,
				       "Error in test definiton file: ");
			FPRINT_MESSAGE(app->log,
				       "\"%s\" is not a json-c object\n",
				       thr_obj->key);
			return err;
		}
		break;

	case json_type_object:
		def_obj = thr_obj->val;
		break;

	default:
		FPRINT_MESSAGE(app->log, "Error in test definiton file: ");
		FPRINT_MESSAGE(app->log, "\"%s\" is not a json-c object\n",
			       thr_obj->key);
		DBG_PRINT("\"%s\" is not a json-c object", thr_obj->key);

		return ERR_CODE(BAD_PARAM_TYPE);
	}

	if (!app->threads) {
		err = util_list_init(&app->threads, thr_free_data);
		if (err != ERR_CODE(PASSED))
			return err;
	}

	thr = calloc(1, sizeof(*thr));
	if (!thr) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	thr->app = app;
	thr->parent_def = thr_obj->val;
	(void)sprintf(thr->name, "Thread %d", thr_num);
	thr->loop = loop;

	err = get_thread_definition(def_obj, thr);
	if (err == ERR_CODE(PASSED)) {
		err = util_list_add_node(app->threads, thr_num, thr);
		if (err == ERR_CODE(PASSED)) {
			if (!pthread_create(&thr->id, NULL, &process_thread,
					    thr))
				return err;

			DBG_PRINT("Thread %u creation %s", thr_num,
				  util_get_strerr());
			return ERR_CODE(FAILED);
		}
	}

	thr_free_data(thr);

	return err;
}

int util_thread_end(struct app_data *app)
{
	int *thr_status = NULL;
	int status = ERR_CODE(PASSED);
	struct node *node = NULL;
	struct thread_data *thr;

	if (!app)
		return ERR_CODE(BAD_ARGS);

	node = util_list_next(app->threads, node, NULL);
	while (node) {
		thr_status = NULL;

		thr = util_list_data(node);
		if (thr) {
			if (pthread_join(thr->id, (void **)&thr_status)) {
				status |= ERR_CODE(FAILED);
				DBG_PRINT("%s exits with %s", thr->name,
					  util_get_strerr());
			}

			DBG_PRINT("%s", thr->name);

			if (thr_status == PTHREAD_CANCELED)
				status |= ERR_CODE(FAILED);
			else
				status |= *thr_status;
		}

		node = util_list_next(app->threads, node, NULL);
	};

	/* Erase Application thread list */
	util_list_clear(app->threads);

	return status;
}

int util_thread_get_ids(const char *name, unsigned int *first,
			unsigned int *last)
{
	int err = ERR_CODE(INTERNAL);
	static const char delim[2] = ":";
	long val;
	char *tmp = NULL;
	char *field = NULL;

	if (!name || !first || !last)
		return ERR_CODE(BAD_ARGS);

	tmp = malloc(strlen(name) - strlen(THREAD_OBJ) + 1);
	if (!tmp) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	strcpy(tmp, name + strlen(THREAD_OBJ));

	/* Get the first thread id */
	field = strtok(tmp, delim);
	if (!field) {
		DBG_PRINT("Missing Thread ID in %s", name);
		goto exit;
	}

	val = strtol(field, NULL, 10);
	if (!val) {
		DBG_PRINT("Thread ID not valid in %s", name);
		goto exit;
	}

	*first = *last = val;

	/* Get the last thread id if any */
	field = strtok(NULL, delim);
	if (field) {
		val = strtol(field, NULL, 10);
		if (!val) {
			DBG_PRINT("Thread ID not valid in %s", name);
			goto exit;
		}

		*last = val;
	}

	if (*last < *first) {
		DBG_PRINT("Wrong Thread ID (%s) first = %u > last %u", name,
			  *first, *last);
		err = ERR_CODE(FAILED);
	}

	err = ERR_CODE(PASSED);

exit:
	free(tmp);

	return err;
}

const char *util_get_thread_name(struct app_data *app)
{
	struct thread_data *thr;

	thr = get_active_thread_data(app);
	if (thr)
		return thr->name;

	return NULL;
}
