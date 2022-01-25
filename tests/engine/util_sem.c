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
#include "util_list.h"
#include "util_sem.h"

struct app_sem {
	char *name;
	sem_t handle;
	bool init;
};

/**
 * free_sem() - Free a semaphore object
 * @arg: Semaphore object
 *
 * If the semaphore was initialized, destroy it from the system
 */
static void free_sem(void *arg)
{
	struct app_sem *sem = arg;

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
static struct app_sem *find_sem(struct llist *lsem, const char *name)
{
	struct app_sem *sem = NULL;
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
 * If the application semaphore list is empty, the function initializes
 * the list.
 * Function allocates the new semaphore object and add it in the list.
 * If an error occurs, the new semaphore is destroyed.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the argument is not correct.
 */
static int register_sem(struct llist **lsem, const char *name,
			struct app_sem **new_sem)
{
	int err;
	struct app_sem *sem = NULL;
	size_t len;

	if (!name || !lsem || !new_sem) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (!*lsem) {
		err = util_list_init(lsem, free_sem);
		if (err != ERR_CODE(PASSED))
			return err;
	}

	sem = calloc(1, sizeof(*sem));
	if (!sem) {
		DBG_PRINT_ALLOC_FAILURE();
		err = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	if (sem_init(&sem->handle, 1, 0)) {
		DBG_PRINT("Semaphore %s failure %s", name, util_get_strerr());
		err = ERR_CODE(FAILED);
		goto exit;
	}

	sem->init = true;

	len = strlen(name);
	if (!len) {
		err = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	sem->name = malloc(len + 1);
	if (!sem->name) {
		DBG_PRINT_ALLOC_FAILURE();
		err = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	strcpy(sem->name, name);

	err = util_list_add_node(*lsem, 0, sem);

exit:
	if (err != ERR_CODE(PASSED)) {
		free_sem(sem);
		sem = NULL;
	}

	*new_sem = sem;

	return err;
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
static int wait_sem(struct thread_data *thr, struct app_sem *sem,
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

		thr->state = WAITING;
		DBG_PRINT("%s is waiting %s for %d seconds",
			  util_get_thread_name(thr->app), sem->name, timeout);

		err = sem_timedwait(&sem->handle, &ts);
		if (err) {
			DBG_PRINT("Semaphore %s wait timeout: %s", sem->name,
				  util_get_strerr());
			res = ERR_CODE(FAILED);
		}
	} else {
		thr->state = WAITING;
		DBG_PRINT("Waiting %s", sem->name);

		err = sem_wait(&sem->handle);
		if (err) {
			DBG_PRINT("Semaphore %s wait infinite: %s", sem->name,
				  util_get_strerr());
			res = ERR_CODE(INTERNAL);
		}
	}

	return res;
}

/**
 * get_wait_sem() - Wait a semaphore before/after operation
 * @thr: Thread data
 * @obj: JSON-C definition thread or operation.
 * @tag: JSON-C semaphore tag name.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_PARAM_TYPE          - Semaphore definition not correct.
 * -INTERNAL                - Internal system error.
 * -BAD_ARGS                - One of the argument is not correct.
 * -FAILED                  - Failure
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 */
static int get_wait_sem(struct thread_data *thr, struct json_object *obj,
			const char *tag)
{
	int err;
	struct app_sem *sem = NULL;
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

	sem = find_sem(thr->app->semaphores, sem_name);
	if (!sem) {
		err = register_sem(&thr->app->semaphores, sem_name, &sem);
		if (err != ERR_CODE(PASSED))
			return err;
	}

	err = wait_sem(thr, sem, sem_timeout);

	return err;
}

/**
 * post_sem_all() - Post all semaphores
 * @app: Application data.
 *
 * Return:
 * PASSED                   - Success.
 * -FAILED                  - Post semaphore failure.
 */
static int post_sem_all(struct app_data *app)
{
	int res = ERR_CODE(PASSED);
	struct app_sem *sem = NULL;
	struct node *node = NULL;

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
	int res = ERR_CODE(PASSED);
	int err;
	struct app_sem *sem = NULL;

	if (!sem_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	DBG_PRINT("%s", sem_name);

	if (strcmp(sem_name, "all"))
		return post_sem_all(app);

	sem = find_sem(app->semaphores, sem_name);
	if (!sem) {
		res = register_sem(&app->semaphores, sem_name, &sem);
		if (res != ERR_CODE(PASSED))
			return res;
	}

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
		}

		break;

	default:
		return ERR_CODE(FAILED);
	}

	return err;
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
