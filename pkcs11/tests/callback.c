// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>
#include <time.h>

#include "local.h"
#include "util_lib.h"
#include "util_multi_process.h"
#include "util_session.h"

#define TIMEOUT_WAIT 2 /* Timeout 2 seconds */

enum sem_id {
	SEM_A_WAIT_SIG = 0,
	SEM_B_WAIT_SIG,
	NB_SEM,
};

struct shared_data {
	sem_t sem[NB_SEM];
};

static int init_shared_data(struct mp_args *args)
{
	int ret;
	struct shared_data *share = args->shm.data;

	if (args->child)
		return 0;

	/* Initialize all semaphores */
	for (int i = 0; i < NB_SEM; i++) {
		ret = sem_init(&share->sem[i], 1, 0);
		if (ret) {
			TEST_OUT("sem_init: %s\n", util_lib_get_strerror());
			break;
		}
	}

	return ret;
}

static int uninit_shared_data(struct mp_args *args)
{
	int ret;
	struct shared_data *share = args->shm.data;

	if (args->child)
		return 0;

	for (int i = 0; i < NB_SEM; i++) {
		ret = sem_destroy(&share->sem[i]);
		if (ret) {
			TEST_OUT("shm_destroyed: %s\n",
				 util_lib_get_strerror());
			break;
		}
	}
	return ret;
}

static int generate_ec_keypair(CK_FUNCTION_LIST_PTR pfunc,
			       CK_SESSION_HANDLE_PTR sess, CK_BBOOL token)
{
	int status;

	CK_RV ret;
	CK_OBJECT_HANDLE hpubkey;
	CK_OBJECT_HANDLE hprivkey;
	CK_MECHANISM genmech = { .mechanism = CKM_EC_KEY_PAIR_GEN };
	CK_BBOOL btrue = CK_TRUE;

	CK_MECHANISM_TYPE key_allowed_mech[] = { CKM_ECDSA };
	CK_ATTRIBUTE pubkey_attrs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_VERIFY, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};
	CK_ATTRIBUTE *privkey_attrs = NULL;
	CK_ULONG nb_privkey_attrs = 0;
	CK_ATTRIBUTE privkey_token[] = {
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &btrue, sizeof(btrue) },
		{ CKA_ALLOWED_MECHANISMS, &key_allowed_mech,
		  sizeof(key_allowed_mech) },
	};

	if (token) {
		privkey_attrs = privkey_token;
		nb_privkey_attrs = ARRAY_SIZE(privkey_token);
	}

	SUBTEST_START(status);

	TEST_OUT("Login to R/W Session as User\n");
	ret = pfunc->C_Login(*sess, CKU_USER, NULL, 0);
	if (CHECK_CK_RV(CKR_OK, "C_Login"))
		goto end;

	TEST_OUT("Generate %sKeypair by curve oid\n", token ? "Token " : "");
	if (CHECK_EXPECTED(util_to_asn1_oid(&pubkey_attrs[0], prime192v1),
			   "ASN1 Conversion"))
		goto end;

	ret = pfunc->C_GenerateKeyPair(*sess, &genmech, pubkey_attrs,
				       ARRAY_SIZE(pubkey_attrs), privkey_attrs,
				       nb_privkey_attrs, &hpubkey, &hprivkey);
	if (CHECK_CK_RV(CKR_OK, "C_GenerateKeyPair"))
		goto end;

	TEST_OUT("Keypair generated by curve oid pub=#%lu priv=#%lu\n", hpubkey,
		 hprivkey);

	status = TEST_PASS;

end:
	TEST_OUT("Logout User");
	ret = pfunc->C_Logout(*sess);
	if (CHECK_CK_RV(CKR_OK, "C_Logout"))
		status = TEST_FAIL;

	if (pubkey_attrs[0].pValue)
		free(pubkey_attrs[0].pValue);

	SUBTEST_END(status);
	return status;
}

static int wait_timeout(sem_t *sem)
{
	int ret;
	struct timespec ts;

	ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (CHECK_EXPECTED(!ret, "clock_gettime: %s\n",
			   util_lib_get_strerror()))
		return ret;

	/* Set wait timeout in seconds */
	ts.tv_sec += TIMEOUT_WAIT;

	ret = sem_timedwait(sem, &ts);
	(void)CHECK_EXPECTED(!ret, "sem_timedwait: %s\n",
			     util_lib_get_strerror());

	return ret;
}

static CK_RV notify_callback(CK_SESSION_HANDLE hsess, CK_NOTIFICATION event,
			     CK_VOID_PTR app)
{
	(void)hsess;
	int ret;
	struct mp_args *args = app;
	struct shared_data *share;

	if (!args)
		return CKR_CANCEL;

	if (event != CKN_SURRENDER)
		return CKR_CANCEL;

	if (CHECK_EXPECTED(args->pid == getpid(),
			   "Current pid=%d expected %d\n", getpid(), args->pid))
		return CKR_CANCEL;

	share = args->shm.data;

	/* Synchronize processes */
	if (args->child) {
		TEST_OUT("Wait Process A signal\n");
		sem_post(&share->sem[SEM_A_WAIT_SIG]);
		ret = wait_timeout(&share->sem[SEM_B_WAIT_SIG]);
	} else {
		TEST_OUT("Wait Process B signal\n");
		sem_post(&share->sem[SEM_B_WAIT_SIG]);
		ret = wait_timeout(&share->sem[SEM_A_WAIT_SIG]);
	}

	if (CHECK_EXPECTED(!ret, "Process synchronization error\n"))
		return CKR_CANCEL;

	return CKR_OK;
}

static int proc_a_callback(struct mp_args *args)
{
	int status = TEST_FAIL;

	struct shared_data *share = args->shm.data;
	CK_SESSION_HANDLE sess = 0;

	TEST_OUT("Process A pid = %d\n", args->pid);

	if (util_open_rw_session_cb(args->pfunc, 0, &notify_callback, args,
				    &sess) == TEST_FAIL)
		goto end;

	sem_post(&share->sem[SEM_B_WAIT_SIG]);
	sem_wait(&share->sem[SEM_A_WAIT_SIG]);

	status = generate_ec_keypair(args->pfunc, &sess, false);

end:
	util_close_session(args->pfunc, &sess);

	return status;
}

static int proc_b_callback(struct mp_args *args)
{
	int status = TEST_FAIL;

	struct shared_data *share = args->shm.data;
	CK_SESSION_HANDLE sess = 0;

	TEST_OUT("Process B pid = %d\n", args->pid);

	if (util_open_rw_session_cb(args->pfunc, 0, &notify_callback, args,
				    &sess) == TEST_FAIL)
		goto end;

	sem_post(&share->sem[SEM_A_WAIT_SIG]);
	sem_wait(&share->sem[SEM_B_WAIT_SIG]);

	status = generate_ec_keypair(args->pfunc, &sess, false);

end:
	util_close_session(args->pfunc, &sess);

	return status;
}

void tests_pkcs11_callback(void *lib_hdl, CK_FUNCTION_LIST_PTR pfunc)
{
	int status;

	int ret;
	struct mp_args mp_args = { 0 };

	mp_args.pid = getpid();
	tests_data.trace_pid = mp_args.pid;

	TEST_START(status);

	mp_args.testname = strrchr(__func__, '_');
	if (CHECK_EXPECTED(mp_args.testname, "Unable to get function name\n"))
		goto end;

	mp_args.testname++;

	mp_args.shm.size = sizeof(struct shared_data);

	ret = util_create_open_shm(&mp_args);
	if (CHECK_EXPECTED(!ret, "Unable to open shm\n"))
		goto end;

	ret = init_shared_data(&mp_args);
	if (CHECK_EXPECTED(!ret, "Unable to initialize shm data\n"))
		goto end;

	if (mp_args.child)
		mp_args.test_func = &proc_b_callback;
	else
		mp_args.test_func = &proc_a_callback;

	mp_args.lib_hdl = lib_hdl;
	mp_args.pfunc = pfunc;

	status = run_multi_process(&mp_args);

end:
	ret = uninit_shared_data(&mp_args);
	if (CHECK_EXPECTED(!ret, "Unable to uninitialize shm data\n"))
		status = TEST_FAIL;

	if (!mp_args.child) {
		ret = util_close_shm(&mp_args);
		if (CHECK_EXPECTED(!ret, "Unable to close shm\n"))
			status = TEST_FAIL;
	}

	TEST_END(status);
}
