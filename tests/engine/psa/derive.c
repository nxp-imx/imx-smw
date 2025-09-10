// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>

#include "derive.h"
#include "types.h"
#include "key.h"
#include "util.h"
#include "util_attr.h"

#include <psa/crypto.h>

#include <stdlib.h>

static psa_status_t input_key_agreement(psa_key_derivation_operation_t *op,
					psa_key_derivation_step_t step,
					struct keypair_psa key,
					struct tbuffer public_key)
{
	return psa_key_derivation_key_agreement(op, step, key.attributes.id,
						public_key.data,
						public_key.length);
}

static psa_status_t input_key(psa_key_derivation_operation_t *op,
			      psa_key_derivation_step_t step,
			      struct keypair_psa key)
{
	return psa_key_derivation_input_key(op, step, key.attributes.id);
}

static psa_status_t output_bytes(psa_key_derivation_operation_t *op,
				 uint8_t *out, size_t length)
{
	return psa_key_derivation_output_bytes(op, out, length);
}

static psa_status_t output_key(psa_key_derivation_operation_t *op,
			       struct keypair_psa *key)
{
	return psa_key_derivation_output_key(&key->attributes, op,
					     &key->attributes.id);
}

int derive_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	psa_algorithm_t alg = PSA_ALG_NONE;
	struct tbuffer info = { 0 };
	struct tbuffer seed = { 0 };
	const char *secret = NULL;
	struct keypair_psa secret_key = { 0 };
	const char *other_secret = NULL;
	struct keypair_psa other_secret_key = { 0 };
	struct key_data key_data = { 0 };
	struct keypair_psa *output_keys = NULL;
	unsigned int nb_output_keys = 0;
	unsigned int i = 0;
	struct tbuffer peer_public_data = { 0 };
	psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
	psa_key_derivation_step_t step = (psa_key_derivation_step_t)0;

	res = util_attr_read_attributes(subtest->params, ALGO_OBJ,
					&algorithm_callback_psa, &alg);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->psa_status = psa_key_derivation_setup(&op, alg);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	res = util_read_json_type(&secret, SECRET_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		res = key_desc_init_psa(&secret_key);
		if (res != ERR_CODE(PASSED))
			goto end;

		res = key_read_descriptor_psa(list_keys(subtest), &secret_key,
					      secret);
		if (res != ERR_CODE(PASSED))
			goto end;

		step = PSA_KEY_DERIVATION_INPUT_SECRET;
		subtest->psa_status =
			psa_key_derivation_input_key(&op, step,
						     secret_key.attributes.id);
		if (subtest->psa_status != PSA_SUCCESS) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}
	}

	res = util_read_json_type(&other_secret, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (other_secret) {
		res = key_desc_init_psa(&other_secret_key);
		if (res != ERR_CODE(PASSED))
			goto end;

		res = key_read_descriptor_psa(list_keys(subtest),
					      &other_secret_key, other_secret);
		if (res != ERR_CODE(PASSED))
			goto end;

		if (other_secret_key.data)
			free(other_secret_key.data);
	}

	res = util_read_json_type(&peer_public_data, PEER_PUB_KEY_OBJ,
				  t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	step = PSA_KEY_DERIVATION_INPUT_OTHER_SECRET;
	if (peer_public_data.data && peer_public_data.length) {
		subtest->psa_status =
			input_key_agreement(&op, step, other_secret_key,
					    peer_public_data);
	} else {
		subtest->psa_status = input_key(&op, step, other_secret_key);
	}

	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	res = util_read_json_type(&info, INFO_OBJ, t_buffer_hex,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		step = PSA_KEY_DERIVATION_INPUT_INFO;
		subtest->psa_status =
			psa_key_derivation_input_bytes(&op, step, info.data,
						       info.length);
		if (subtest->psa_status != PSA_SUCCESS) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}
	}

	res = util_read_json_type(&seed, SEED_OBJ, t_buffer_hex,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		step = PSA_KEY_DERIVATION_INPUT_SEED;
		subtest->psa_status =
			psa_key_derivation_input_bytes(&op, step, seed.data,
						       seed.length);
		if (subtest->psa_status != PSA_SUCCESS) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}
	}

	res = key_read_descriptors_psa(subtest, OP_OUTPUT_OBJ, &nb_output_keys,
				       &output_keys);
	if (res != ERR_CODE(PASSED))
		goto end;

	for (i = 0; i < nb_output_keys; i++) {
		if (output_keys[i].data)
			subtest->psa_status =
				output_bytes(&op, output_keys[i].data,
					     output_keys[i].data_length);
		else
			subtest->psa_status = output_key(&op, &output_keys[i]);
		if (subtest->psa_status != PSA_SUCCESS) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}

		key_prepare_key_data_psa(&output_keys[i], &key_data);
		res = util_key_update_node(list_keys(subtest),
					   output_keys[i].name, &key_data);
	}

end:
	psa_key_derivation_abort(&op);

	if (peer_public_data.data)
		free(peer_public_data.data);

	if (output_keys) {
		for (i = 0; i < nb_output_keys; i++) {
			if (output_keys[i].data)
				free(output_keys[i].data);
		}

		free(output_keys);
	}

	if (seed.data)
		free(seed.data);

	if (info.data)
		free(info.data);

	return res;
}
