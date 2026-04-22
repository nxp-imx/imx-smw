// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_crypto_key_mgr.h"
#include "ele_crypto_key_group_mng.h"
#include "ele_crypto_internal.h"

#include "utils.h"
#include "utils_ex.h"

status_t ele_open_key_service(s3mu_t *mu, uint32_t keystore_handle_id,
			      uint32_t *key_handle_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[KEY_MNG_OPEN_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = KEY_MNG_OPEN;	      /* KEY_MNG_OPEN Command Header */
	tmsg[1] = keystore_handle_id; /* Session handle ID */
	tmsg[2] =
		0x00000000u; /* User Input address extension (UIA) - not used */
	tmsg[3] =
		0x00000000u; /* User Output address extension (UOA) - not used */
	tmsg[4] = 0x00000000u; /* Flag (reserved) */
	tmsg[5] = s3mu_compute_msg_crc(tmsg, KEY_MNG_OPEN_SIZE - 1u);

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_MNG_OPEN_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == KEY_MNG_OPEN_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read Key Management Handle ID data */
		*key_handle_id = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_close_key_service(s3mu_t *mu, uint32_t key_handle_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[KEY_MNG_OPEN_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = KEY_MNG_CLOSE; /* KEY_MNG_CLOSE Command Header */
	tmsg[1] = key_handle_id; /* Key Management handle ID */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_MNG_CLOSE_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == KEY_MNG_CLOSE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_generate_key(s3mu_t *mu, uint32_t key_handle_id,
			  ele_gen_key_t *conf, uint32_t *key_id,
			  uint16_t *out_size, bool monotonic, bool sync)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[KEY_GEN_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uint32_t flags = 0u;
	uintptr_t pub_key_phys = 0u;
	void *pub_key_addr = NULL;

	if (!mu || !conf || !key_id || !out_size)
		return STATUS_INVALID_ARGUMENT;

	if (conf->key_group > 100u)
		return STATUS_OUT_OF_RANGE;

	if (conf->pub_key_addr && conf->pub_key_size > 0u) {
		pub_key_addr = smw_utils_shared_memory_alloc(conf->pub_key_addr,
							     conf->pub_key_size,
							     &pub_key_phys);
		if (!pub_key_addr)
			return STATUS_FAIL;
	}

	/* Set flags */
	if (monotonic)
		flags |= SYNC_MONOTONIC;

	if (sync)
		flags |= SYNC_OP;

	tmsg[0] = KEY_GEN;	 /* KEY_GEN Command Header */
	tmsg[1] = key_handle_id; /* Key handle ID */
	tmsg[2] = conf->key_id;	 /* Key ID (0 = FW will choose) */
	tmsg[3] = (uint32_t)conf->key_group << SHIFT_16 |
		  conf->pub_key_size; /* Key Group | Public key size */
	tmsg[4] = (uint32_t)conf->key_size << SHIFT_16 |
		  conf->key_type;		/* Key size | Key Type */
	tmsg[5] = (uint32_t)conf->key_lifetime; /* Lifetime */
	tmsg[6] = (uint32_t)conf->key_usage;	/* Key Usage */
	tmsg[7] = conf->permitted_alg;		/* Permitted algorithms */
	tmsg[8] = conf->key_lifecycle;		/* Key Lifecycle (1 = OPEN); */
	tmsg[9] = flags; /* FLAGS (Monotonic counter, SYNC) */
	tmsg[10] = (uint32_t)
		pub_key_phys; /* Output buffer address for public key */
	tmsg[11] = s3mu_compute_msg_crc(tmsg, KEY_GEN_SIZE - 1u);

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_GEN_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] != KEY_GEN_RESPONSE_HDR) {
		status = STATUS_FAIL;
		goto end;
	}

	/* Header is OK, check for success */
	if (rmsg[1] == RESPONSE_SUCCESS) {
		/* Read Key pair ID data and key size */
		*key_id = rmsg[2];
		*out_size = (uint16_t)(rmsg[3] & KEY_GEN_KEY_SIZE_MASK);
		status = STATUS_SUCCESS;
	} else if (rmsg[1] == RESPONSE_ERROR_SIZE) {
		/* Save expected key size */
		*out_size = (uint16_t)(rmsg[3] & KEY_GEN_KEY_SIZE_MASK);
		status = STATUS_ELE_BUFFER_TOO_SMALL;
	} else if (rmsg[1] == RESPONSE_ERROR_GROUP_FULL) {
		status = STATUS_ELE_KEY_GROUP_FULL;
	} else {
		status = STATUS_FAIL;
	}

end:
	smw_utils_shared_memory_free(pub_key_addr, conf->pub_key_size,
				     conf->pub_key_addr);

	return status;
}

status_t ele_generate_pub_key(s3mu_t *mu, uint32_t keystore_handle_id,
			      uint32_t key_id, uint32_t *output,
			      uint32_t out_key_size, uint16_t *out_size)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[KEY_GEN_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uintptr_t output_phys = 0u;
	void *output_addr = NULL;

	if (!mu || !output || !out_size)
		return STATUS_INVALID_ARGUMENT;

	output_addr = smw_utils_shared_memory_alloc(output, out_key_size,
						    &output_phys);
	if (!output_addr)
		return STATUS_FAIL;

	tmsg[0] = PUB_KEY_GEN;		 /* KEY_GEN Command Header */
	tmsg[1] = keystore_handle_id;	 /* Keystore handle ID */
	tmsg[2] = key_id;		 /* Asymmetric Key ID */
	tmsg[3] = 0u;			 /* MSB address (not used) */
	tmsg[4] = (uint32_t)output_phys; /* Public key output address */
	tmsg[5] = out_key_size; /* Length in bytes of output key buffer */
	tmsg[6] = s3mu_compute_msg_crc(tmsg, PUB_KEY_GEN_SIZE - 1u);

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, PUB_KEY_GEN_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] != PUB_KEY_GEN_RESPONSE_HDR) {
		status = STATUS_FAIL;
		goto end;
	}

	/* Header is OK, check for success */
	if (rmsg[1] == RESPONSE_SUCCESS) {
		*out_size = (uint16_t)(rmsg[2] & PUB_KEY_GEN_KEY_SIZE_MASK);

		smw_utils_dcache_invalidate(output, *out_size);

		status = STATUS_SUCCESS;
	} else if (rmsg[1] == RESPONSE_ERROR_SIZE) {
		*out_size = (uint16_t)(rmsg[2] & PUB_KEY_GEN_KEY_SIZE_MASK);
		status = STATUS_ELE_BUFFER_TOO_SMALL;
	} else {
		status = STATUS_FAIL;
	}

end:
	smw_utils_shared_memory_free(output_addr, out_key_size, output);

	return status;
}

status_t ele_delete_key(s3mu_t *mu, uint32_t key_handle_id, uint32_t key_id,
			bool monotonic, bool sync)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[KEY_DEL_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uint32_t flags = 0u;

	if (!mu)
		return STATUS_INVALID_ARGUMENT;

	/* Set flags */
	if (monotonic)
		flags |= SYNC_MONOTONIC;

	if (sync)
		flags |= SYNC_OP;

	tmsg[0] = KEY_DEL;	     /* KEY_DEL Command Header */
	tmsg[1] = key_handle_id;     /* Key management handle ID */
	tmsg[2] = key_id;	     /* Key ID */
	tmsg[3] = flags << SHIFT_16; /* FLAGS (Monotonic counter, SYNC) */

	/* Send message to Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_DEL_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check if response header corresponds to the sent command and if success */
	if (rmsg[0] == KEY_DEL_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_get_key_attribute(s3mu_t *mu, uint32_t key_handle_id,
			       uint32_t key_id,
			       ele_key_attribute_t *key_attribute)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[GET_ATTRIBUTE_SIZE] = { 0u };
	uint32_t rmsg[GET_ATTRIBUTE_RSP_SIZE] = { 0u };

	/****************** BBSM program ELE message ***********************/
	tmsg[0] = GET_ATTRIBUTE; /* Get Attribute Command Header */
	tmsg[1] = key_handle_id; /* Key Management handle ID */
	tmsg[2] = key_id;	 /* Key ID */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_ATTRIBUTE_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_ATTRIBUTE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		SMW_UTILS_MEMCPY(key_attribute, &rmsg[2u],
				 sizeof(ele_key_attribute_t));
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_import_key(s3mu_t *mu, uint32_t key_handle_id, uint8_t *input,
			uint32_t input_size, bool key_group_auto,
			uint16_t key_group_id, ele_import_key_option_t option,
			bool sync, bool monotonic, uint32_t *key_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[IMPORT_KEY_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uint32_t flags = 0u;
	uintptr_t input_phys = 0u;
	void *input_addr = NULL;

	if (!input || !input_size || !key_id)
		return STATUS_INVALID_ARGUMENT;

	input_addr =
		smw_utils_shared_memory_alloc(input, input_size, &input_phys);
	if (!input_addr)
		return STATUS_FAIL;

	/* Set the option, sync, monotonic, and the automatic key group selection flags */
	flags = (uint32_t)option;

	if (monotonic)
		flags |= (uint32_t)1u << IMPORT_KEY_MONOTONIC_FLAG_SHIFT;

	if (sync)
		flags |= (uint32_t)1u << IMPORT_KEY_SYNC_FLAG_SHIFT;

	if (!key_group_auto)
		/* If the key group is not chosen automatically, set the flag */
		flags |= (uint32_t)1u << IMPORT_KEY_GROUP_AUTO_FLAG_SHIFT;

	/****************** Load key blob message ***********************/
	tmsg[0] = IMPORT_KEY;		/* Import Key Command Header */
	tmsg[1] = key_handle_id;	/* Key Management Handle ID */
	tmsg[2] = flags;		/* Flags */
	tmsg[3] = (uint32_t)input_phys; /* The input TLV payload */
	tmsg[4] = input_size;		/* Size of the input */
	tmsg[5] =
		(uint32_t)(option == IMPORT_KEY_OPTION_ELE ?
				   key_group_id :
				   0u); /* Key Group ID if ELE option is used */
	tmsg[6] = s3mu_compute_msg_crc(tmsg, IMPORT_KEY_SIZE - 1u); /* CRC */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, IMPORT_KEY_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == IMPORT_KEY_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS) {
		/* Save the returned key ID on success */
		*key_id = rmsg[2];

		status = STATUS_SUCCESS;
	} else {
		status = STATUS_FAIL;
	}

end:
	smw_utils_shared_memory_free(input_addr, input_size, NULL);
	return status;
}
