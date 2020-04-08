/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * struct hdl - HSM handlers
 * @session: Session handle.
 * @key_store: Key store service flow handle.
 * @key_management: Key management service flow handle.
 * @signature_gen: Signature generation service flow handle.
 * @signature_ver: Signature verification service flow handle.
 * @hash: Hash service flow handle.
 *
 * This structure stores the HSM handlers managed by the SMW library.
 */
struct hdl {
	hsm_hdl_t session;
	hsm_hdl_t key_store;
	hsm_hdl_t key_management;
	hsm_hdl_t signature_gen;
	hsm_hdl_t signature_ver;
	hsm_hdl_t hash;
};
