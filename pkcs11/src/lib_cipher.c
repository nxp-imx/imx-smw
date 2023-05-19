// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "lib_cipher.h"
#include "lib_device.h"
#include "lib_session.h"
#include "lib_object.h"

#include "util.h"
#include "trace.h"

#define DES_IV_LEN	 8
#define AES_IV_LEN	 16
#define MAX_COUNTER_BITS 128

/**
 * check_cipher_mech_params() -  Check cipher mechanism parameters
 * @pmechanism: Pointer to mechanism
 * @ctx: Pointer to cipher context
 *
 * Store cipher context parameters iv and iv length, if valid.
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - @pmechanism parameters are invalid
 * CKR_MECHANISM_INVALID			  - @pmechanism.mechanism is invalid
 * CKR_OK                             - Success
 */
static CK_RV check_cipher_mech_params(CK_MECHANISM_PTR pmechanism,
				      struct lib_cipher_ctx *ctx)
{
	CK_AES_CTR_PARAMS_PTR ctr_params = NULL_PTR;

	switch (pmechanism->mechanism) {
	case CKM_AES_CBC:
		if (!pmechanism->pParameter) {
			DBG_TRACE("CBC mode: iv is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (pmechanism->ulParameterLen != AES_IV_LEN) {
			DBG_TRACE("CBC mode: iv length is not correct");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ctx->iv = pmechanism->pParameter;
		ctx->iv_length = pmechanism->ulParameterLen;
		break;

	case CKM_DES_CBC:
	case CKM_DES3_CBC:
		if (!pmechanism->pParameter) {
			DBG_TRACE("CBC mode: iv is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (pmechanism->ulParameterLen != DES_IV_LEN) {
			DBG_TRACE("CBC mode: iv length is not correct");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ctx->iv = pmechanism->pParameter;
		ctx->iv_length = pmechanism->ulParameterLen;
		break;

	case CKM_AES_CTR:
		if (pmechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS)) {
			DBG_TRACE("ulParameterLen error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ctr_params = (CK_AES_CTR_PARAMS_PTR)pmechanism->pParameter;

		if (ctr_params->ulCounterBits > MAX_COUNTER_BITS) {
			DBG_TRACE("ulCounterBits error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ctx->iv = ctr_params->cb;
		ctx->iv_length = sizeof(ctr_params->cb);
		break;

	case CKM_AES_CTS:
		if (!pmechanism->pParameter) {
			DBG_TRACE("CTS mode: iv is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ctx->iv = pmechanism->pParameter;
		ctx->iv_length = pmechanism->ulParameterLen;
		break;

	case CKM_AES_XTS:
		if (!pmechanism->pParameter) {
			DBG_TRACE("XTS mode: iv is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ctx->iv = pmechanism->pParameter;
		ctx->iv_length = pmechanism->ulParameterLen;
		break;

	case CKM_AES_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

/**
 * set_key_value() -  sets key buffer value and key length
 * @hsession: Session handle
 * @ctx: Pointer to cipher context
 *
 * For CKM_AES_XTS mechanism, fetch the key attributes (key buffer value and key length)
 * and store them in the cipher context parameters key_value and key_len.
 *
 * Return:
 * CKR_HOST_MEMORY                     - Memory allocation error
 * CKR_OBJECT_HANDLE_INVALID           - Object not found
 * CKR_CRYPTOKI_NOT_INITIALIZED        - Context not initialized
 * CKR_GENERAL_ERROR                   - No slot defined
 * CKR_SESSION_HANDLE_INVALID          - Session Handle invalid
 * CKR_FUNCTION_FAILED                 - Function failure
 * CKR_ATTRIBUTE_SENSITIVE             - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL                - One of the attributes length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID          - One of the attributes is not present
 * CKR_OK                              - Success
 */
static CK_RV set_key_value(CK_SESSION_HANDLE hsession,
			   struct lib_cipher_ctx *ctx)
{
	CK_RV ret = CKR_OK;

	CK_ULONG key_len = 0;

	ctx->key_value = NULL_PTR;
	ctx->key_len = 0;

	CK_ATTRIBUTE key_length_attr[] = { {
		CKA_VALUE_LEN,
		NULL_PTR,
		0,
	} };

	CK_ATTRIBUTE key_value_attr[] = { {
		CKA_VALUE,
		NULL_PTR,
		0,
	} };

	if (ctx->cipher_mech == CKM_AES_XTS) {
		key_length_attr[0].pValue = &key_len;
		key_length_attr[0].ulValueLen = sizeof(key_len);

		/* Get the key length */
		ret = libobj_get_attribute(hsession, ctx->hkey, key_length_attr,
					   ARRAY_SIZE(key_length_attr));
		if (ret != CKR_OK)
			goto end;

		ctx->key_value = calloc(1, key_len * sizeof(*ctx->key_value));
		if (!ctx->key_value) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		key_value_attr[0].pValue = ctx->key_value;
		key_value_attr[0].ulValueLen =
			sizeof(*ctx->key_value) * key_len;

		/* Get the key value */
		ret = libobj_get_attribute(hsession, ctx->hkey, key_value_attr,
					   ARRAY_SIZE(key_value_attr));
		if (ret != CKR_OK)
			goto end;

		ctx->key_len = key_len;
	}

end:
	return ret;
}

/**
 * cancel_operation() - Cancel the multi-part cipher operation, if active
 * @hsession: Session handle
 * @op_flag: Operation flag
 *
 * Check if any multi-part cipher operation is active.
 * If a multi-part operation is active, cancel the operation
 * and remove the operation context.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_DEVICE_ERROR	                  - Device failure
 * CKR_OK                             - Success
 *
 */
static CK_RV cancel_operation(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;

	struct lib_cipher_ctx *ctx = NULL;

	CK_MECHANISM mechanism = { 0 };

	ret = libsess_find_opctx(hsession, op_flag, &mechanism, (void **)&ctx);
	if (ret == CKR_OPERATION_NOT_INITIALIZED) {
		ret = CKR_OK;
		goto end;
	}

	if (ret != CKR_OK)
		goto end;

	switch (ctx->current_state) {
	case OP_INIT:
		ret = libsess_remove_opctx(hsession, op_flag);
		break;

	case OP_UPDATE:
		if (ctx->context)
			ret = libsess_cancel_opctx(hsession, op_flag,
						   (void **)&ctx->context);
		else
			ret = libsess_remove_opctx(hsession, op_flag);

		break;

	default:
		break;
	}

end:

	if (ctx) {
		if (ret != CKR_OK) {
			if (ctx->key_value) {
				free(ctx->key_value);
				ctx->key_value = NULL_PTR;
			}

			free(ctx);
		}
	}

	return ret;
}

CK_RV lib_encrypt_decrypt_init(CK_SESSION_HANDLE hsession,
			       CK_MECHANISM_PTR pmechanism,
			       CK_OBJECT_HANDLE hkey, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	struct lib_cipher_ctx *ctx = NULL;
	CK_BBOOL key_op = false;
	CK_ATTRIBUTE iskey_op[] = {
		{ CKA_DECRYPT, &key_op, sizeof(key_op) },
	};

	DBG_TRACE("Initialize %s operation",
		  op_flag == CKF_ENCRYPT ? "Encrypt" : "Decrypt");

	if (pmechanism) {
		/* Validate mechanism operation flag */
		ret = libsess_validate_mechanism(hsession, pmechanism, op_flag);
		if (ret != CKR_OK)
			goto end;

	} else {
		/*
		 * Check if any multi-part cipher operation is active.
		 * If a multi-part operation is active, cancel the operation
		 * and remove the operation context.
		 */
		return cancel_operation(hsession, op_flag);
	}

	if (op_flag == CKF_ENCRYPT)
		iskey_op[0].type = CKA_ENCRYPT;

	ret = libobj_get_attribute(hsession, hkey, iskey_op,
				   ARRAY_SIZE(iskey_op));
	if (ret == CKR_ATTRIBUTE_TYPE_INVALID) {
		ret = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto end;
	}

	if (ret != CKR_OK)
		goto end;

	if (!key_op) {
		ret = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto end;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	ctx->cipher_mech = pmechanism->mechanism;
	ctx->iv_length = 0;
	ctx->iv = NULL;
	ctx->context = NULL_PTR;

	ret = check_cipher_mech_params(pmechanism, ctx);
	if (ret != CKR_OK)
		goto end;

	/* Set context key handle */
	ctx->hkey = hkey;

	ret = set_key_value(hsession, ctx);
	if (ret != CKR_OK)
		goto end;

	/* Add operation context to list */
	ret = libsess_add_opctx(hsession, op_flag, pmechanism, ctx);

end:

	if (ctx) {
		if (ret != CKR_OK) {
			if (ctx->key_value) {
				free(ctx->key_value);
				ctx->key_value = NULL_PTR;
			}

			free(ctx);
		} else {
			/* Set the current state */
			ctx->current_state = OP_INIT;
		}
	}

	return ret;
}

CK_RV lib_encrypt_decrypt(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pinput,
			  CK_ULONG input_length, CK_BYTE_PTR poutput,
			  CK_ULONG_PTR poutput_length, CK_FLAGS op_flag,
			  enum op_state state)
{
	CK_RV ret = CKR_OK;
	CK_MECHANISM mechanism = { 0 };
	struct lib_cipher_ctx *ctx = NULL;
	struct lib_cipher_params params = { 0 };

	if (state == OP_ONE_SHOT || state == OP_UPDATE) {
		if (!input_length) {
			ret = (op_flag == CKF_ENCRYPT) ?
				      CKR_DATA_LEN_RANGE :
				      CKR_ENCRYPTED_DATA_LEN_RANGE;
			goto end;
		}

		if (!pinput) {
			ret = (op_flag == CKF_ENCRYPT) ?
				      CKR_DATA_INVALID :
				      CKR_ENCRYPTED_DATA_INVALID;
			goto end;
		}
	}

	if (!poutput_length) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	/* Check that operation is initialized */
	ret = libsess_find_opctx(hsession, op_flag, &mechanism, (void **)&ctx);
	if (ret != CKR_OK)
		goto end;

	switch (ctx->current_state) {
	case OP_INIT:
		break;

	case OP_ONE_SHOT:
		if (state != OP_ONE_SHOT) {
			ret = CKR_OPERATION_NOT_INITIALIZED;
			goto end;
		}

		break;

	case OP_UPDATE:
		if (state != OP_UPDATE && state != OP_FINAL)
			return CKR_OPERATION_NOT_INITIALIZED;

		break;

	case OP_FINAL:
		if (state != OP_FINAL) {
			ret = CKR_OPERATION_NOT_INITIALIZED;
			goto end;
		}

		break;

	default:
		ret = CKR_OPERATION_NOT_INITIALIZED;
		goto end;
	}

	params.op_flag = op_flag;
	params.ctx = ctx;
	params.pinput = pinput;
	params.input_length = input_length;
	params.poutput = poutput;
	params.output_length = *poutput_length;
	params.state = state;

	/* Run operation */
	ret = libdev_operate_mechanism(hsession, &mechanism, &params);
	if (ret == CKR_BUFFER_TOO_SMALL || ret == CKR_OK) {
		/* Update output data buffer length */
		*poutput_length = params.output_length;

		if (ret == CKR_OK) {
			ctx->current_state = state;
			if (state == OP_UPDATE)
				return ret;
		}

		if (ret == CKR_BUFFER_TOO_SMALL || !poutput)
			return ret;
	}

end:
	if (ctx && ctx->key_value) {
		free(ctx->key_value);
		ctx->key_value = NULL_PTR;
	}

	if (ret != CKR_OK) {
		if (ctx && ctx->context) {
			/*
			 * Cancel the on-going multipart operation and
			 * remove operation context.
			 */
			(void)libsess_cancel_opctx(hsession, op_flag,
						   (void **)&ctx->context);

		} else {
			(void)libsess_remove_opctx(hsession, op_flag);
		}

	} else {
		ret = libsess_remove_opctx(hsession, op_flag);
	}

	return ret;
}
