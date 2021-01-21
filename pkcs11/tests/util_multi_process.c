// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "local.h"
#include "os_mutex.h"
#include "util_lib.h"
#include "util_multi_process.h"

extern const char *progname;

static int initialize_process(CK_FUNCTION_LIST_PTR pfunc)
{
	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	return pfunc->C_Initialize(&init);
}

static int run_test(struct mp_args *args)
{
	int status = TEST_FAIL;
	CK_RV ret;

	ret = initialize_process(args->pfunc);
	if (CHECK_CK_RV(CKR_OK, "Initialize process"))
		goto end;

	status = args->test_func(args);

end:
	ret = args->pfunc->C_Finalize(NULL);
	if (ret != CKR_OK)
		status = TEST_FAIL;

	return status;
}

static int process_b(struct mp_args *args)
{
	int ret;
	const char *const test_argv[] = { progname, "-t", args->testname,
					  NULL };

	ret = execvp(progname, (char *const *)test_argv);

	exit(ret);
}

int util_close_shm(struct mp_args *args)
{
	int ret = 0;

	TEST_OUT("Close shared mem %s\n", args->shm.name);
	if (args->shm.fd) {
		ret = shm_unlink(args->shm.name);
		if (ret)
			TEST_OUT("shm_unlink: %s\n", util_lib_get_strerror());
	}

	return ret;
}

int util_create_open_shm(struct mp_args *args)
{
	int ret;

	ret = sprintf(args->shm.name, "/%s", args->testname);
	if (ret <= 0) {
		TEST_OUT("Unable tp build shared mem name (%d)\n", ret);
		return ret;
	}

	TEST_OUT("Create/open shared mem %s\n", args->shm.name);

	/*
	 * Create a Shared Memory named @args->shm.name. Name must
	 * start must with a slash
	 */
	ret = shm_open(args->shm.name, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (ret == -1) {
		if (__errno_location() && errno == EEXIST) {
			args->child = 1;
			ret = shm_open(args->shm.name, O_RDWR, 0);
		}
	}

	if (ret == -1) {
		TEST_OUT("shm_open: %s %d\n", util_lib_get_strerror(), ret);
		return ret;
	}

	args->shm.fd = ret;

	ret = ftruncate(args->shm.fd, args->shm.size);
	if (ret) {
		TEST_OUT("ftruncate: %s\n", util_lib_get_strerror());
		goto end;
	}

	/* Map the shared data into address space */
	args->shm.data = mmap(NULL, args->shm.size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, args->shm.fd, 0);
	if (args->shm.data == MAP_FAILED) {
		TEST_OUT("mmap: %s\n", util_lib_get_strerror());
		ret = -1;
	}

end:
	if (ret) {
		util_close_shm(args);
		args->shm.fd = 0;
	}

	return ret;
}

int run_multi_process(struct mp_args *args)
{
	int status = TEST_FAIL;
	int pid;
	int wpid;
	int wstatus;

	if (CHECK_EXPECTED(args, "Error args is NULL"))
		return status;

	if (CHECK_EXPECTED(args->pfunc, "Error args->pfunc is NULL"))
		return status;

	if (args->child)
		return run_test(args);

	pid = fork();
	if (!pid) {
		/*
		 * This part of code should not be run if caller
		 * is using a shared memory 'util_create_open_shm()'.
		 * Shared memory is setting the args->child field to
		 * 1 if shared memory already exist.
		 */
		process_b(args);
		return status;
	}

	status = run_test(args);

	wpid = wait(&wstatus);
	TEST_OUT("Wait child pid=%d expected pid=%d\n", wpid, pid);
	if (CHECK_EXPECTED(wpid == pid, "Wait child pid=%d expected pid=%d\n",
			   wpid, pid))
		status = TEST_FAIL;
	else if (CHECK_EXPECTED(wstatus == 0, "Child error %d", wstatus))
		status = TEST_FAIL;

	return status;
}
