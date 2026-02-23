// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <tss2/tss2_mu.h>

#include <string.h>

#include "utils.h"
#include "commands.h"
#include "trace.h"

uint32_t handle_startup(tcti_smw_context_t *ctx, uint16_t tag,
			const uint8_t *cmd, size_t cmd_size)
{
	uint32_t resp_size = TPM_HEADER_SIZE; /* header only */
	TPM2_SU startup_type = TPM2_SU_STATE;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;

	tss2_rc = param_su_unmarshal(cmd, cmd_size, &startup_type);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (startup_type != TPM2_SU_CLEAR) {
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	ctx->initialized = 1;
	tss2_rc = build_rc_response(ctx, resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_shutdown(tcti_smw_context_t *ctx, uint16_t tag,
			 const uint8_t *cmd, size_t cmd_size)
{
	uint32_t resp_size = TPM_HEADER_SIZE; /* header only */
	TPM2_SU shutdown_type = TPM2_SU_STATE;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;

	tss2_rc = param_su_unmarshal(cmd, cmd_size, &shutdown_type);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (shutdown_type != TPM2_SU_CLEAR) {
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	ctx->initialized = 0;
	tss2_rc = build_rc_response(ctx, resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_getcapability(tcti_smw_context_t *ctx, uint16_t tag,
			      const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	uint32_t prop = 0;
	TPMS_TAGGED_PROPERTY *tagged_prop = NULL;
	TPM2_HANDLE saved_handle = 0;

	/* Input parameters */
	TPM2_CAP capability = 0;
	uint32_t property = 0;
	uint32_t property_count = 0;
	uint32_t max_prop = 0;

	/* Output parameters */
	TPMI_YES_NO more_data = TPM2_NO;
	TPMS_CAPABILITY_DATA cap_data = { 0 };
	TPMU_CAPABILITIES *data = &cap_data.data;

	/* Response construction */
	size_t resp_offset = TPM_HEADER_SIZE;
	uint32_t total_resp_size = 0;
	/*
	 * Workaround: Some TSS2 Marshal functions don't handle NULL buffer correctly
	 * for size calculation.
	 * cap_data_size must be compute manually in the switch case statement.
	 */
	size_t cap_data_size = sizeof(TPM2_CAP);
	uint8_t i = 0;

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal input parameters */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &capability);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &property);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
					   &property_count);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Prepare capability data based on request */
	cap_data.capability = capability;

	switch (capability) {
	case TPM2_CAP_TPM_PROPERTIES:
		/* Return minimal TPM properties */
		data->tpmProperties.count = 0;

		if (ADD_OVERFLOW(property, property_count, &max_prop)) {
			tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}
		for (prop = property;
		     prop < max_prop &&
		     data->tpmProperties.count < TPM2_MAX_TPM_PROPERTIES;
		     prop++) {
			tagged_prop =
				&data->tpmProperties
					 .tpmProperty[data->tpmProperties.count];

			tagged_prop->property = prop;

			switch (prop) {
			case TPM2_PT_MAX_DIGEST:
				tagged_prop->value = TPM2_SHA512_DIGEST_SIZE;
				data->tpmProperties.count++;
				break;

			case TPM2_PT_FAMILY_INDICATOR:
				tagged_prop->value =
					TPM2_SPEC_FAMILY; /* "2.0" */
				data->tpmProperties.count++;
				break;

			case TPM2_PT_LEVEL:
				tagged_prop->value = 0; /* Level 0 */
				data->tpmProperties.count++;
				break;

			case TPM2_PT_REVISION:
				tagged_prop->value =
					184; /* Specification version is v184 */
				data->tpmProperties.count++;
				break;

			/* Add other properties as needed */
			default:
				/* Property not supported - skip it */
				break;
			}
		}
		cap_data_size += sizeof(uint32_t); /* count */
		cap_data_size += data->tpmProperties.count *
				 sizeof(TPMS_TAGGED_PROPERTY);
		/* Could add properties here if needed */
		break;

	case TPM2_CAP_ALGS:
		/* Return supported algorithms */
		data->algorithms.count = 0;
		cap_data_size += sizeof(uint32_t); /* count */
		cap_data_size +=
			data->algorithms.count * sizeof(TPMS_ALG_PROPERTY);
		/* Could add algorithms here if needed */
		break;

	case TPM2_CAP_COMMANDS:
		/* Return supported commands */
		data->command.count = 0;
		cap_data_size += sizeof(uint32_t); /* count field */
		cap_data_size += data->command.count * sizeof(TPMA_CC);
		/* Could add commands here if needed */
		break;

	case TPM2_CAP_HANDLES:
		/* Return handles based on the requested range */
		data->handles.count = 0;
		cap_data_size += sizeof(uint32_t); /* count field */

		/* Determine which type of handles to return based on property */
		if ((property >> TPM2_HR_SHIFT) == TPM2_HT_LOADED_SESSION) {
			/* Loaded session handles requested */
			DBG_TRACE("Loaded session requested (property=0x%08x)\n",
				  property);

			for (i = 0; i < SMW_MAX_SESSIONS; i++) {
				if (!ctx->sessions[i].active)
					continue;

				if (ctx->sessions[i].saved)
					continue;

				if (data->handles.count >= TPM2_MAX_CAP_HANDLES)
					continue;

				data->handles.handle[data->handles.count++] =
					ctx->sessions[i].handle;
			}
		} else if ((property >> TPM2_HR_SHIFT) ==
			   TPM2_HT_SAVED_SESSION) {
			/* Saved session handles requested */
			DBG_TRACE("Saved sessions requested (property=0x%08x)\n",
				  property);

			for (i = 0; i < SMW_MAX_SESSIONS; i++) {
				if (!ctx->sessions[i].active)
					continue;

				if (!ctx->sessions[i].saved)
					continue;

				if (data->handles.count >= TPM2_MAX_CAP_HANDLES)
					continue;

				/*
				 * Return handle as TPM_HT_HMAC_SESSION (0x02xxxxxx)
				 * regardless original type according to TPM2 spec
				 *
				 * Reference: TPM 2.0 Part3-Commands,Section 30.2.1
				 * (website link: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3-Version-184_pub.pdf
				 */
				saved_handle = (ctx->sessions[i].handle &
						TPM2_HR_HANDLE_MASK) |
					       TPM2_HR_HMAC_SESSION;
				data->handles.handle[data->handles.count++] =
					saved_handle;
			}
		} else if ((property >> TPM2_HR_SHIFT) == TPM2_HT_TRANSIENT) {
			/* Transient object handles requested */
			DBG_TRACE(/* Without this comment clang-format does not */
				  /* meet the checkpatch requirement. */
				  "Transient objects requested (property=0x%08x)\n",
				  property);

			/* TODO: Add transient object tracking */
			/* For now, return empty list (no transient objects) */
			data->handles.count = 0;
		} else if ((property >> TPM2_HR_SHIFT) == TPM2_HT_PERSISTENT) {
			/* Persistent object handles requested */
			DBG_TRACE(/* Without this comment clang-format does not */
				  /* meet the checkpatch requirement. */
				  "Persistent objects requested (property=0x%08x)\n",
				  property);

			/* Return empty list (no persistent objects) */
			data->handles.count = 0;
		} else if ((property >> TPM2_HR_SHIFT) == TPM2_HT_NV_INDEX) {
			DBG_TRACE("NV Index requested (property=0x%08x)\n",
				  property);
			/* TODO: List NV index, probably to mock */
			data->handles.count = 0;
		} else {
			/* Unknown handle range */
			DBG_TRACE("Unknown handle range (property=0x%08x)\n",
				  property);
			data->handles.count = 0;
		}

		cap_data_size += data->handles.count * sizeof(TPM2_HANDLE);

		break;

	case TPM2_CAP_PCRS:
		/* Return PCR banks information */
		data->assignedPCR.count = ctx->pcr_bank_count;
		for (i = 0; i < ctx->pcr_bank_count; i++) {
			data->assignedPCR.pcrSelections[i].hash =
				ctx->pcr_banks[i].hash_alg;
			/* Only PCR0 is supported */
			data->assignedPCR.pcrSelections[i].sizeofSelect =
				SMW_PCR_SELECT_SIZE;
			/* Initialize PCR selection bitmap */
			memset(data->assignedPCR.pcrSelections[i].pcrSelect, 0,
			       sizeof(data->assignedPCR.pcrSelections[i]
					      .pcrSelect));
			/* Mark PCR 0 as available (bit 0 of first byte) */
			data->assignedPCR.pcrSelections[i].pcrSelect[0] = 0x01;
		}

		cap_data_size += sizeof(uint32_t); /* count field */
		cap_data_size +=
			data->assignedPCR.count * sizeof(TPMS_PCR_SELECTION);
		/* Could add PCR banks here if needed */
		break;

	default:
		/* Unknown capability - return empty data */
		DBG_TRACE("Unknown capability requested: 0x%08x\n", capability);
		break;
	}

	total_resp_size = TPM_HEADER_SIZE + sizeof(TPMI_YES_NO) + cap_data_size;

	/* 4. Build response */
	tss2_rc = build_rc_response(ctx, total_resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

	/* 5. Marshal response data */
	tss2_rc = Tss2_MU_UINT8_Marshal(more_data, ctx->resp_buf,
					ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPMS_CAPABILITY_DATA_Marshal(&cap_data, ctx->resp_buf,
						       ctx->resp_size,
						       &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("GetCapability response size: %zu bytes\n", resp_offset);

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
