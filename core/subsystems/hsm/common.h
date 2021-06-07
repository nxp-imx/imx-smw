/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

/**
 * struct hdl - HSM handles
 * @session: Session handle
 * @key_store: Key store service flow handle
 * @key_management: Key management service flow handle
 * @signature_gen: Signature generation service flow handle
 * @signature_ver: Signature verification service flow handle
 * @hash: Hash service flow handle
 * @rng: RNG service flow handle
 * @cipher: Cipher service flow handle
 *
 * This structure stores the HSM handles managed by the SMW library.
 */
struct hdl {
	hsm_hdl_t session;
	hsm_hdl_t key_store;
	hsm_hdl_t key_management;
	hsm_hdl_t signature_gen;
	hsm_hdl_t signature_ver;
	hsm_hdl_t hash;
	hsm_hdl_t rng;
	hsm_hdl_t cipher;
};

/**
 * load() - Load the HSM library.
 *
 * This function loads the HSM library.
 *
 * Return:
 * error code.
 */
int load(void);

/**
 * unload() - Unload the HSM library.
 *
 * This function unloads the HSM library.
 *
 * Return:
 * error code.
 */
int unload(void);

/**
 * get_handles_struct() - Get the HSM handles.
 *
 * This function gets the HSM handles.
 *
 * Return:
 * pointer to the HSM handles structure.
 */
struct hdl *get_handles_struct(void);

/**
 * hsm_key_handle() - Handle the Key operations.
 * @hdl: Pointer to the HSM handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the Key operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool hsm_key_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status);

/**
 * hash_handle() - Handle the Hash operation.
 * @hdl: Pointer to the HSM handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the Hash operation.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool hash_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		 int *status);

/**
 * sign_verify_handle() - Handle the Sign and Verify operations.
 * @hdl: Pointer to the HSM handles structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the Sign and Verify operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool sign_verify_handle(struct hdl *hdl, enum operation_id operation_id,
			void *args, int *status);
