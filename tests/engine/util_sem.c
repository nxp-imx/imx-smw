// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <semaphore.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "util.h"
#include "util_ipc.h"
#include "util_sem.h"

/* Semaphore string list delimiter */
#define SEM_LIST_DELIMITER ";"

/**
 * free_sem() - Free a semaphore object
 * @arg: Semaphore object
 *
 * If the semaphore was initialized, destroy it from the system
 */
static void free_sem(void *arg)
{
	struct sem_obj *sem = arg;

	if (!sem)
		return;

	if (sem->init)
		sem_destroy(&sem->handle);

	if (sem->name)
		free(sem->name);

	free(sem);
}

/**
 * find_sem() - Find a semaphore in the application list
 * @lsem: Pointer to semaphore linked list.
 * @name: Name of the semaphore.
 *
 * Return:
 * Pointer to the semaphore object if found,
 * otherwise NULL
 */
static struct sem_obj *find_sem(struct llist *lsem, const char *name)
{
	struct sem_obj *sem = NULL;
	struct node *node = NULL;

	if (!name)
		return NULL;

	do {
		sem = NULL;
		node = util_list_next(lsem, node, NULL);
		if (node)
			sem = util_list_data(node);

		if (sem && sem->name)
			if (!strcmp(name, sem->name))
				break;
	} while (node);

	return sem;
}

/**
 * register_sem() - Register a new semaphore linked to the application.
 * @lsem: Pointer to semaphore linked list.
 * @name: Name of the semaphore.
 * @new_sem: Return the new semaphore object.
 *
 * Function allocates the new semaphore object and add it in the list.
 * If an error occurs, the new semaphore is destroyed.
 *
 * Return:
 * PASSED                  - Success.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -BAD_ARGS               - One of the argument is not correct.
 */
static int register_sem(struct llist *lsem, const char *name,
			struct sem_obj **new_sem)
{
	int res = ERR_CODE(PASSED);
	struct sem_obj *sem = NULL;
	size_t len;

	if (!name || !lsem || !new_sem) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	util_list_lock(lsem);

	sem = find_sem(lsem, name);
	if (sem)
		goto exit;

	sem = calloc(1, sizeof(*sem));
	if (!sem) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	if (sem_init(&sem->handle, 0, 0)) {
		DBG_PRINT("Semaphore %s failure %s", name, util_get_strerr());
		res = ERR_CODE(FAILED);
		goto exit;
	}

	sem->init = true;

	len = strlen(name);
	if (!len) {
		res = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	sem->name = malloc(len + 1);
	if (!sem->name) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	strcpy(sem->name, name);

	res = util_list_add_node_nl(lsem, 0, sem);

exit:
	if (res != ERR_CODE(PASSED)) {
		if (sem)
			free_sem(sem);

		sem = NULL;
	}

	*new_sem = sem;

	util_list_unlock(lsem);

	return res;
}

/**
 * wait_sem() - Wait a semaphore with or without timeout
 * @thr: Thread data
 * @sem: Pointer to the semaphore object.
 * @timeout: Timeout in seconds to wait if not 0.
 *
 * Return:
 * PASSED     - Success.
 * -INTERNAL  - Internal system error.
 * -BAD_ARGS  - One of the argument is not correct.
 * -FAILED    - Wait semaphore failed on timeout.
 */
static int wait_sem(struct thread_data *thr, struct sem_obj *sem,
		    unsigned int timeout)
{
	int res = ERR_CODE(PASSED);
	int err;
	struct timespec ts;

	if (!sem) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (timeout) {
		err = clock_gettime(CLOCK_REALTIME, &ts);
		if (err) {
			DBG_PRINT("Clock gettime: %s", util_get_strerr());
			return ERR_CODE(INTERNAL);
		}

		ts.tv_sec += timeout;

		thr->state = STATE_WAITING;
		DBG_PRINT("Waiting %s for %d seconds", sem->name, timeout);

		err = sem_timedwait(&sem->handle, &ts);
		if (err) {
			DBG_PRINT("Semaphore %s wait timeout: %s", sem->name,
				  util_get_strerr());
			res = ERR_CODE(FAILED);
		}
	} else {
		thr->state = STATE_WAITING;
		DBG_PRINT("Waiting %s", sem->name);

		err = sem_wait(&sem->handle);
		if (err) {
			DBG_PRINT("Semaphore %s wait infinite: %s", sem->name,
				  util_get_strerr());
			res = ERR_CODE(INTERNAL);
		}
	}

	thr->state = STATE_RUNNING;

	return res;
}

/**
 * get_wait_sem() - Wait a semaphore before/after operation
 * @thr: Thread data
 * @obj: JSON-C definition thread or operation.
 * @tag: JSON-C semaphore tag name.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_PARAM_TYPE         - Semaphore definition not correct.
 * -INTERNAL               - Internal system error.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
static int get_wait_sem(struct thread_data *thr, struct json_object *obj,
			const char *tag)
{
	int err;
	struct sem_obj *sem = NULL;
	struct json_object *sem_obj = NULL;
	struct json_object *oval = NULL;
	const char *sem_name = NULL;
	int nb_elem;
	int sem_timeout = 0;

	if (!thr || !thr->app) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (!thr->app->is_multithread)
		return ERR_CODE(PASSED);

	if (!obj || !tag) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/*
	 * Waiting semaphore format possible are:
	 * - "name"
	 * - ["name"]
	 * - ["name", timeout]
	 */
	err = util_read_json_type(&sem_obj, tag, t_sem, obj);

	if (err != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (err == ERR_CODE(VALUE_NOTFOUND))
			err = ERR_CODE(PASSED);

		return err;
	}

	switch (json_object_get_type(sem_obj)) {
	case json_type_string:
		/* Get the semaphore name */
		sem_name = json_object_get_string(sem_obj);
		break;

	case json_type_array:
		nb_elem = json_object_array_length(sem_obj);
		if (nb_elem > 2) {
			DBG_PRINT("%s badly defined", tag);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		/* Get the semaphore name */
		oval = json_object_array_get_idx(sem_obj, 0);
		if (json_object_get_type(oval) != json_type_string) {
			DBG_PRINT("%s 1st index must be the name", tag);
			return ERR_CODE(BAD_PARAM_TYPE);
		}
		sem_name = json_object_get_string(oval);

		if (nb_elem == 1)
			break;

		/* Get the semaphore wait timeout */
		oval = json_object_array_get_idx(sem_obj, 1);
		if (json_object_get_type(oval) != json_type_int) {
			DBG_PRINT("%s 2nd index must be the timeout", tag);
			return ERR_CODE(BAD_PARAM_TYPE);
		}
		sem_timeout = json_object_get_int(oval);

		break;

	default:
		return ERR_CODE(FAILED);
	}

	err = register_sem(thr->app->semaphores, sem_name, &sem);
	if (err == ERR_CODE(PASSED))
		err = wait_sem(thr, sem, sem_timeout);

	return err;
}

/**
 * post_sem_all() - Post all semaphores
 * @app: Application data.
 *
 * Return:
 * PASSED                  - Success.
 * -FAILED                 - Post semaphore failure.
 */
static int post_sem_all(struct app_data *app)
{
	int res = ERR_CODE(PASSED);
	struct sem_obj *sem = NULL;
	struct node *node = NULL;

	util_list_lock(app->semaphores);

	do {
		sem = NULL;
		node = util_list_next(app->semaphores, node, NULL);
		if (node) {
			sem = util_list_data(node);

			if (sem && sem_post(&sem->handle)) {
				DBG_PRINT("%s", sem->name);
				res = ERR_CODE(FAILED);
			}
		}
	} while (node);

	util_list_unlock(app->semaphores);

	return res;
}

/**
 * post_sem() - Post a or all semaphore(s)
 * @app: Application data.
 * @sem_name: Name of the semaphore.
 *
 * If the semaphore doesn't exist, register it.
 * If the name of the semaphore is "all", post all registered
 * semaphores.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal system error.
 * -BAD_ARGS                - One of the argument is not correct.
 * -FAILED                  - Post semaphore failure.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 */
static int post_sem(struct app_data *app, const char *sem_name)
{
	int res;
	int err;
	struct sem_obj *sem = NULL;

	if (!sem_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	DBG_PRINT("%s", sem_name);

	if (!strcmp(sem_name, "all"))
		return post_sem_all(app);

	res = register_sem(app->semaphores, sem_name, &sem);
	if (res != ERR_CODE(PASSED))
		return res;

	err = sem_post(&sem->handle);
	if (err) {
		DBG_PRINT("Semaphore %s post: %s", sem_name, util_get_strerr());
		res = ERR_CODE(INTERNAL);
	}

	return res;
}

/**
 * get_post_sem() - Post a semaphore before/after operation
 * @thr: Thread data
 * @obj: JSON-C definition thread or operation.
 * @tag: JSON-C semaphore tag name.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_PARAM_TYPE         - Semaphore definition not correct.
 * -INTERNAL               - Internal system error.
 * -BAD_ARGS               - One of the argument is not correct.
 * -FAILED                 - Failure.
 * -INTERNAL_OUT_OF_MEMORY - Allocation error
 */
static int get_post_sem(struct thread_data *thr, struct json_object *obj,
			const char *tag)
{
	int err;
	struct json_object *sem_obj = NULL;
	struct json_object *oval = NULL;
	const char *sem_name = NULL;
	int nb_elem = 0;
	int idx;

	if (!thr || !thr->app) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (!thr->app->is_multithread)
		return ERR_CODE(PASSED);

	if (!obj || !tag) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/*
	 * Posting semaphore format possible are:
	 * - "name"
	 * - ["name"]
	 * - ["name 1", "name 2"]
	 * - "all"
	 */
	err = util_read_json_type(&sem_obj, tag, t_sem, obj);

	if (err != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (err == ERR_CODE(VALUE_NOTFOUND))
			err = ERR_CODE(PASSED);

		return err;
	}

	switch (json_object_get_type(sem_obj)) {
	case json_type_string:
		/* Get the semaphore name */
		sem_name = json_object_get_string(sem_obj);
		err = post_sem(thr->app, sem_name);
		break;

	case json_type_array:
		nb_elem = json_object_array_length(sem_obj);

		for (idx = 0; idx < nb_elem; idx++) {
			/* Get the semaphore name */
			oval = json_object_array_get_idx(sem_obj, idx);
			if (json_object_get_type(oval) != json_type_string) {
				DBG_PRINT("%s index %d must be a name", tag,
					  idx);
				err = ERR_CODE(BAD_PARAM_TYPE);
				break;
			}
			sem_name = json_object_get_string(oval);
			err = post_sem(thr->app, sem_name);
			if (err != ERR_CODE(PASSED))
				break;
		}

		break;

	default:
		return ERR_CODE(FAILED);
	}

	return err;
}

/**
 * post_to_sem() - Post a or all semaphore(s) to an application
 * @app: Active appplication data.
 * @obj: JSON-C semaphore object definition.
 *
 * Coding format of the semaphore object @obj is:
 * - ["app 1", "name"]
 * - ["app 1", ["name 1", "name 2"]]
 * - ["app 1", "all"]
 * - ["all", "all"]
 *
 * Return:
 * PASSED                   - Success.
 * or any error code (see enum err_num)
 */
static int post_to_sem(struct app_data *app, struct json_object *obj)
{
	int err = ERR_CODE(FAILED);
	struct ipc_op op = { .cmd = IPC_POST_SEM };
	struct json_object *sem_obj = NULL;
	struct json_object *oval = NULL;
	const char *app_name = NULL;
	const char *sem_name = NULL;
	char *op_name = op.args.name;
	size_t cnt_char = 0;
	int nb_char = 0;
	int nb_elem = 0;
	int idx;

	/* First element of the @obj must be the application name or "all" */
	sem_obj = json_object_array_get_idx(obj, 0);
	if (json_object_get_type(sem_obj) != json_type_string)
		return ERR_CODE(BAD_PARAM_TYPE);

	app_name = json_object_get_string(sem_obj);

	/* Second element of the @obj must be a string or an array of strings */
	sem_obj = json_object_array_get_idx(obj, 1);
	switch (json_object_get_type(sem_obj)) {
	case json_type_string:
		sem_name = json_object_get_string(sem_obj);
		if (strlen(sem_name) + 1 <= sizeof(op.args.name)) {
			(void)sprintf(op_name, "%s", sem_name);
			err = util_ipc_send(app, app_name, &op);
		}
		break;

	case json_type_array:
		nb_elem = json_object_array_length(sem_obj);

		if (!nb_elem)
			break;

		err = ERR_CODE(PASSED);

		for (idx = 0; idx < nb_elem; idx++) {
			/* Get the semaphore name */
			oval = json_object_array_get_idx(sem_obj, idx);
			if (json_object_get_type(oval) != json_type_string) {
				DBG_PRINT("%s index %d must be a name",
					  app_name, idx);
				err = ERR_CODE(BAD_PARAM_TYPE);
				break;
			}

			sem_name = json_object_get_string(oval);

			/*
			 * Calculate the remaining operation name length
			 * to contain the "sem_name" + null termination and
			 * if not the last semaphore list, the delimiter.
			 */
			cnt_char += strlen(sem_name) + 1;
			if (idx < nb_elem - 1)
				cnt_char += 1;

			if (cnt_char > sizeof(op.args.name)) {
				DBG_PRINT("Operation name too short");
				err = ERR_CODE(FAILED);
				break;
			}

			nb_char = sprintf(op_name, "%s", sem_name);
			if (nb_char >= 0) {
				op_name += nb_char;
				if (idx < nb_elem - 1) {
					nb_char = sprintf(op_name, "%s",
							  SEM_LIST_DELIMITER);
					if (nb_char >= 0)
						op_name += nb_char;
				}
			}

			if (nb_char < 0) {
				DBG_PRINT("sprintf returned %d", nb_char);
				err = ERR_CODE(FAILED);
				break;
			}
		}

		if (err == ERR_CODE(PASSED))
			err = util_ipc_send(app, app_name, &op);
		break;

	default:
		DBG_PRINT("%s semaphore(s) bad definition", app_name);
		err = ERR_CODE(BAD_PARAM_TYPE);
	}

	return err;
}

/**
 * get_post_to_sem() - Post a semaphore to application(s) before/after
 * @app: Current Application data
 * @obj: JSON-C definition application, thread or operation.
 * @tag: JSON-C semaphore tag name.
 *
 * Return:
 * PASSED                  - Success.
 * or any error code (see enum err_num)
 */
static int get_post_to_sem(struct app_data *app, struct json_object *obj,
			   const char *tag)
{
	int err;
	struct json_object *sem_obj = NULL;
	struct json_object *oapp = NULL;
	int nb_elem = 0;
	int nb_apps = 0;
	int idx;

	if (!app || !app->test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (app->test->nb_apps < 2)
		return ERR_CODE(PASSED);

	if (!obj || !tag) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/*
	 * Posting semaphore to application(s) format possible are:
	 * - ["app 1", "name"]
	 * - ["app 1", ["name 1", "name 2"]]
	 * - ["app 1", "all"]
	 * - [
	 *     ["app 1", "name"],
	 *     ["app 2", ["name 1", "name 2"]
	 *   ]
	 * - ["all", "all"]
	 */
	err = util_read_json_type(&sem_obj, tag, t_sem, obj);

	if (err != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (err == ERR_CODE(VALUE_NOTFOUND))
			err = ERR_CODE(PASSED);

		return err;
	}

	if (json_object_get_type(sem_obj) != json_type_array) {
		DBG_PRINT("%s index %d must be an array of at least 2 elements",
			  tag);
		return ERR_CODE(FAILED);
	}

	/* At least array is 2 elements */
	nb_elem = json_object_array_length(sem_obj);
	if (nb_elem < 2) {
		DBG_PRINT("%s index %d must be at least 2 elements", tag);
		return ERR_CODE(FAILED);
	}

	/*
	 * Get if this is an array of array:
	 *   [
	 *     ["app 1", "name"],
	 *     ["app 2", ["name 1", "name 2"]
	 *   ]
	 *
	 * Or if this a single or all application post
	 *  ["app 1", ...]
	 *  ["all", "all"]
	 */

	oapp = json_object_array_get_idx(sem_obj, 0);
	switch (json_object_get_type(oapp)) {
	case json_type_string:
		err = post_to_sem(app, sem_obj);
		break;

	case json_type_array:
		nb_apps = json_object_array_length(oapp);

		for (idx = 0; idx < nb_apps; idx++) {
			/* Get the first application's semaphores
			 *   [
			 *     ["app 1", "name"],
			 *     ["app 2", ["name 1", "name 2"]
			 *   ]
			 */
			sem_obj = json_object_array_get_idx(oapp, idx);
			if (json_object_get_type(sem_obj) != json_type_array) {
				DBG_PRINT("%s index %d must be an array", tag,
					  idx);
				err = ERR_CODE(BAD_PARAM_TYPE);
				break;
			}

			err = post_to_sem(app, sem_obj);
			if (err != ERR_CODE(PASSED))
				break;
		}

		break;

	default:
		return ERR_CODE(FAILED);
	}

	return err;
}

int util_sem_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, free_sem);
}

int util_sem_wait_before(struct thread_data *thr, struct json_object *obj)
{
	return get_wait_sem(thr, obj, WAIT_BEFORE);
}

int util_sem_wait_after(struct thread_data *thr, struct json_object *obj)
{
	return get_wait_sem(thr, obj, WAIT_AFTER);
}

int util_sem_post_before(struct thread_data *thr, struct json_object *obj)
{
	return get_post_sem(thr, obj, POST_BEFORE);
}

int util_sem_post_after(struct thread_data *thr, struct json_object *obj)
{
	return get_post_sem(thr, obj, POST_AFTER);
}

int util_sem_post_to_before(struct app_data *app, struct json_object *obj)
{
	return get_post_to_sem(app, obj, POST_TO_BEFORE);
}

int util_sem_post_to_after(struct app_data *app, struct json_object *obj)
{
	return get_post_to_sem(app, obj, POST_TO_AFTER);
}

void util_sem_ipc_post(struct app_data *app, const char *sem_name)
{
	char *sem = NULL;

	if (!app || !sem_name) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	/* Get the first thread id */
	sem = strtok((char *)sem_name, SEM_LIST_DELIMITER);
	while (sem) {
		(void)post_sem(app, sem);
		sem = strtok(NULL, SEM_LIST_DELIMITER);
	}
}
