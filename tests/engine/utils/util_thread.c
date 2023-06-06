// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_cond.h"
#include "util_list.h"
#include "util_log.h"
#include "util_mutex.h"
#include "util_sem.h"
#include "util_thread.h"
#include "run_thread.h"

static int get_active_thread_data(struct app_data *app,
				  struct thread_data **thr)
{
	struct node *node = NULL;
	pthread_t tid;

	if (!app || !thr)
		return ERR_CODE(BAD_ARGS);

	tid = pthread_self();

	util_list_lock(app->threads);
	node = util_list_next(app->threads, node, NULL);
	while (node) {
		*thr = util_list_data(node);

		if (*thr && pthread_equal((*thr)->id, tid))
			break;

		node = util_list_next(app->threads, node, NULL);
		*thr = NULL;
	};

	util_list_unlock(app->threads);

	return ERR_CODE(PASSED);
}

static void thr_free_data(void *data)
{
	struct thread_data *thr_data = data;

	if (!thr_data)
		return;

	if (thr_data->state == STATE_RUNNING ||
	    thr_data->state == STATE_WAITING)
		(void)pthread_cancel(thr_data->id);

	if (thr_data->stat.status_array)
		free(thr_data->stat.status_array);

	free(thr_data);
}

static int read_thread_loop(struct json_object_iter *thr_obj, int *loop,
			    struct json_object **thr_def)
{
	struct json_object *otmp;

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

static int cancel_all_threads(struct app_data *app)
{
	int status = ERR_CODE(PASSED);
	struct node *node = NULL;
	struct thread_data *thr;

	node = util_list_next(app->threads, node, NULL);
	while (node) {
		thr = util_list_data(node);
		if (thr) {
			switch (thr->state) {
			case STATE_EXITED:
				break;

			default:
				DBG_PRINT("Cancelling %s", thr->name);

				thr->state = STATE_CANCELED;
				thr->status = ERR_CODE(THREAD_CANCELED);

				if (pthread_cancel(thr->id))
					DBG_PRINT("%s cancel with %s",
						  thr->name, util_get_strerr());

				util_thread_log(thr);
				break;
			}

			if (status == ERR_CODE(PASSED))
				status = thr->status;
		}

		node = util_list_next(app->threads, node, NULL);
	};

	return status;
}

static void *process_thread_ends(void *arg)
{
	struct thread_ends *thr_end = arg;
	int *thr_status = NULL;
	struct node *node = NULL;
	struct thread_data *thr;

	if (!thr_end || !thr_end->app) {
		DBG_PRINT_BAD_ARGS();
		exit(ERR_CODE(BAD_ARGS));
	}

	thr_end->state = STATE_RUNNING;

	node = util_list_next(thr_end->app->threads, node, NULL);
	while (node) {
		thr_status = NULL;

		thr = util_list_data(node);
		if (thr) {
			if (pthread_join(thr->id, (void **)&thr_status))
				DBG_PRINT("%s exits with %s", thr->name,
					  util_get_strerr());

			if (thr_status == PTHREAD_CANCELED)
				DBG_PRINT("%s canceled", thr->name);
			else
				DBG_PRINT("%s complete with %d status",
					  thr->name, *thr_status);
		}

		node = util_list_next(thr_end->app->threads, node, NULL);
	};

	thr_end->status = util_cond_signal(thr_end->cond);
	if (thr_end->status != ERR_CODE(PASSED))
		DBG_PRINT("Signal thread ends error %d", thr_end->status);

	thr_end->state = STATE_EXITED;

	return &thr_end->status;
}

/**
 * thread_ends_start() - Start the thread waiting ends of test threads
 * @app: Application data
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the argument is not correct.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Thread creating failure.
 */
static int thread_ends_start(struct app_data *app)
{
	int res;
	struct thread_ends *thr;

	if (!app)
		return ERR_CODE(BAD_ARGS);

	thr = calloc(1, sizeof(*thr));
	if (!thr) {
		DBG_PRINT_ALLOC_FAILURE();
		return INTERNAL_OUT_OF_MEMORY;
	}

	thr->app = app;
	app->thr_ends = thr;

	/*
	 * Create the mutex and condition to run the thread waiting
	 * all threads completion.
	 */
	thr->lock = util_mutex_create();
	if (!thr->lock) {
		DBG_PRINT("Can't create mutex");
		res = ERR_CODE(FAILED);
		goto exit;
	}

	thr->cond = util_cond_create();
	if (!thr->cond) {
		DBG_PRINT("Can't create condition");
		res = ERR_CODE(FAILED);
		goto exit;
	}

	if (pthread_create(&thr->id, NULL, &process_thread_ends, thr)) {
		DBG_PRINT("Thread creation %s", util_get_strerr());
		res = ERR_CODE(FAILED);
	} else {
		res = ERR_CODE(PASSED);
	}

exit:
	if (res != ERR_CODE(PASSED))
		(void)util_thread_ends_destroy(app);

	return res;
}

static int log_header(struct thread_data *thr, char *str)
{
	struct app_data *app = NULL;
	struct test_data *test = NULL;
	int nb_char = 0;
	int err = 0;

	app = thr->app;
	if (app && app->test)
		test = app->test;

	if (app && test && test->is_multi_apps && strlen(app->name)) {
		err = sprintf(str, "(%s - %d) ", app->name, getpid());
		if (err < 0) {
			DBG_PRINT("Error (%d) %s", err, util_get_strerr());
			return err;
		}

		nb_char += err;
	}

	if (strlen(thr->name)) {
		err = sprintf(&str[nb_char], "[%s - 0x%lx] ", thr->name,
			      thr->id);
		if (err < 0) {
			DBG_PRINT("Error (%d) %s", err, util_get_strerr());
			return err;
		}

		nb_char += err;
	}

	return nb_char;
}

static void subtest_log(struct thread_data *thr)
{
	struct test_data *test = NULL;
	int nb_char = 0;
	char str[256] = { 0 };
	const char *error = NULL;
	struct subtest_data *subtest = NULL;

	if (!thr->app || !thr->app->test) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	test = thr->app->test;
	nb_char = log_header(thr, str);
	if (nb_char < 0)
		return;

	subtest = thr->subtest;
	if (*subtest->status == ERR_CODE(API_STATUS_NOK))
		error = get_string_status(subtest->api_status, subtest->api);

	(void)sprintf(&str[nb_char], "%s: %s", subtest->name,
		      util_get_err_code_str(*subtest->status));

	/* Additional error message if any */
	if (error)
		util_log_status(test, "%s (%s)\n", str, error);
	else
		util_log_status(test, "%s\n", str);
}

static void thread_log(struct thread_data *thr)
{
	struct test_data *test = NULL;
	int nb_char = 0;
	char str[256] = { 0 };

	if (!thr->app || !thr->app->test) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	test = thr->app->test;

	nb_char = log_header(thr, str);
	if (nb_char < 0)
		return;

	/* This is the status of the thread */
	if (thr->status == ERR_CODE(PASSED))
		(void)sprintf(&str[nb_char], "%s\n",
			      util_get_err_code_str(thr->status));
	else
		(void)sprintf(&str[nb_char], "%s (%s)\n",
			      util_get_err_code_str(ERR_CODE(FAILED)),
			      util_get_err_code_str(thr->status));

	util_log_status(test, "%s\n", str);
}

static void thread_stat_log(struct thread_data *thr)
{
	struct test_data *test = NULL;
	int nb_char = 0;
	int err = 0;
	char str[256] = { 0 };
	int rate_passed = 0;
	int total = 0;
	int fails = 0;

	if (!thr->app || !thr->app->test) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	test = thr->app->test;

	nb_char = log_header(thr, str);
	if (nb_char < 0)
		return;

	/* Print the subtests statistic */
	total = thr->stat.number;
	if (thr->loop)
		total *= thr->loop;

	fails = total - thr->stat.passed;

	if (thr->stat.ran && total) {
		rate_passed = 100 * thr->stat.passed;
		rate_passed /= total;
	}

	err = sprintf(&str[nb_char],
		      "\t%d%% subtests passed, %d failed out of %d",
		      rate_passed, fails, total);

	if (err >= 0)
		nb_char += err;
	else
		DBG_PRINT("Error (%d) %s", err, util_get_strerr());

	if (total - thr->stat.ran) {
		err = sprintf(&str[nb_char], " (missing %d)",
			      total - thr->stat.ran);
		if (err >= 0)
			nb_char += err;
		else
			DBG_PRINT("Error (%d) %s", err, util_get_strerr());
	}

	if (thr->loop)
		(void)sprintf(&str[nb_char], " in %d loops\n", thr->loop);
	else
		(void)sprintf(&str[nb_char], "\n");

	util_log_status(test, "%s\n", str);
}

int util_thread_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, &thr_free_data, LIST_ID_TYPE_UINT);
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
			FPRINT_MESSAGE(app, "Error in test definiton file: ");
			FPRINT_MESSAGE(app, "\"%s\" is not a json-c object\n",
				       thr_obj->key);
			return err;
		}
		break;

	case json_type_object:
		def_obj = thr_obj->val;
		break;

	default:
		FPRINT_MESSAGE(app, "Error in test definiton file: ");
		FPRINT_MESSAGE(app, "\"%s\" is not a json-c object\n",
			       thr_obj->key);
		DBG_PRINT("\"%s\" is not a json-c object", thr_obj->key);

		return ERR_CODE(BAD_PARAM_TYPE);
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

	err = util_get_subdef(&thr->def, def_obj, thr->app->test);
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

int util_get_thread_name(struct app_data *app, const char **name)
{
	int res;
	struct thread_data *thr = NULL;

	if (!app || !name)
		return ERR_CODE(BAD_ARGS);

	res = get_active_thread_data(app, &thr);
	if (res == ERR_CODE(PASSED) && thr)
		*name = thr->name;

	return res;
}

int util_thread_ends_destroy(struct app_data *app)
{
	int res = ERR_CODE(PASSED);
	int err;

	if (!app)
		return ERR_CODE(BAD_ARGS);

	if (!app->thr_ends)
		return res;

	res = util_mutex_destroy(&app->thr_ends->lock);
	if (res != ERR_CODE(PASSED))
		DBG_PRINT("Destroy mutex %d", res);

	err = util_cond_destroy(&app->thr_ends->cond);
	if (err != ERR_CODE(PASSED)) {
		DBG_PRINT("Destroy condition %d", err);
		res = (res == ERR_CODE(PASSED)) ? err : res;
	}

	free(app->thr_ends);
	app->thr_ends = NULL;

	return res;
}

int util_thread_ends_wait(struct app_data *app)
{
	int res;
	int status;

	if (!app)
		return ERR_CODE(BAD_ARGS);

	/*
	 * Create and start the thread waiting all test threads
	 */
	res = thread_ends_start(app);
	if (res == ERR_CODE(PASSED)) {
		res = util_cond_wait(app->thr_ends->cond, app->thr_ends->lock,
				     app->timeout);

		if (res != ERR_CODE(PASSED))
			DBG_PRINT("Application thread completion error %d",
				  res);

		if (app->thr_ends->id && app->thr_ends->state != STATE_EXITED) {
			if (pthread_cancel(app->thr_ends->id))
				DBG_PRINT("Cancel Thread error: %s",
					  util_get_strerr());
		}
	}

	/* Ensure all threads are canceled to exit application properly */
	status = cancel_all_threads(app);
	res = (res == ERR_CODE(PASSED)) ? status : res;

	return res;
}

void util_thread_log(struct thread_data *thr)
{
	if (!thr) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	if (thr->subtest) {
		subtest_log(thr);
		return;
	}

	if (thr->app && thr->app->is_multithread)
		thread_log(thr);

	thread_stat_log(thr);
}
