/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __CRYPTO__H__
#define __CRYPTO__H__

#include "smw/names.h"
#include "smw/attr.h"

#include "psa/crypto_types.h"

/**
 * get_hash_algo_name() - Get SMW hash algo name.
 * @alg: PSA hash algorithm.
 *
 * This function returns the SMW hash algorithm name corresponding to the
 * given PSA hash algorithm.
 *
 * Return:
 * SMW hash algo name.
 */
smw_hash_algo_t get_hash_algo_name(psa_algorithm_t alg);

/**
 * get_hash_algo_attr() - Get SMW hash algo attribute.
 * @alg: PSA hash algorithm.
 *
 * This function returns the SMW hash algorithm attribute corresponding to the
 * given PSA hash algorithm.
 *
 * Return:
 * SMW hash algo attribute.
 */
smw_attr_algo_t get_hash_algo_attr(psa_algorithm_t alg);

#endif /* __CRYPTO__H__ */
