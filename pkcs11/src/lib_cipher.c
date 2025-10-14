// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "lib_cipher.h"
#include "lib_device.h"
#include "lib_session.h"
#include "lib_object.h"
#include "libobj_types.h"

#include "util.h"
#include "trace.h"

#define DES_IV_LEN	 8
#define AES_IV_LEN	 16
#define SM4_IV_LEN	 16
#define MAX_COUNTER_BITS 128

/**
 * destroy_context() - Destroy cipher context
 * @ctx: Pointer to cipher context
 *
 */
static void destroy_context(struct lib_cipher_ctx *ctx)
{
	if (ctx) {
		if (ctx->key_value)
			free(ctx->key_value);

		if (ctx->iv)
			free(ctx->iv);

		if (ctx->tag)
			free(ctx->tag);

		if (ctx->input)
			free(ctx->input);

		free(ctx);
	}
}

/**
 * set_iv_value() -  Set IV buffer value and IV length
 * @iv: IV buffer address
 * @ivlen: IV buffer length
 * @ctx: Pointer to cipher context
 *
 * Allocate an IV buffer in the internal context and copy user IV given value.
 *
 * Return:
 * CKR_HOST_MEMORY                     - Memory allocation error
 * CKR_ARGUMENTS_BAD                   - Bad arguments
 * CKR_OK                              - Success
 */
static CK_RV set_iv_value(CK_VOID_PTR iv, CK_ULONG ivlen,
			  struct lib_cipher_ctx *ctx)
{
	if (!ctx)
		return CKR_ARGUMENTS_BAD;

	if (!ivlen)
		return CKR_OK;

	if (ctx->current_state == OP_INIT ||
	    ctx->current_state == OP_ONE_SHOT) {
		if (ctx->iv && ctx->iv_length != ivlen) {
			free(ctx->iv);
			ctx->iv = NULL;
		}

		if (!ctx->iv) {
			ctx->iv = calloc(1, ivlen);
			if (!ctx->iv)
				return CKR_HOST_MEMORY;

			ctx->iv_length = ivlen;
			ctx->fixed_iv_length = ivlen;
		}
	}

	if (!ctx->iv || ctx->iv_length != ivlen)
		return CKR_MECHANISM_PARAM_INVALID;

	memcpy(ctx->iv, iv, ivlen);

	return CKR_OK;
}

/**
 * set_tag_value() -  Set Tag buffer value and Tag length
 * @tag: Tag buffer address
 * @taglen: Tag buffer length
 * @ctx: Pointer to cipher context
 *
 * Allocate a Tag buffer in the internal context and copy Tag given value.
 *
 * Return:
 * CKR_HOST_MEMORY                     - Memory allocation error
 * CKR_ARGUMENTS_BAD                   - Bad arguments
 * CKR_OK                              - Success
 */
static CK_RV set_tag_value(CK_VOID_PTR tag, CK_ULONG taglen, CK_FLAGS op_flag,
			   struct lib_cipher_ctx *ctx)
{
	if (!ctx || !taglen)
		return CKR_ARGUMENTS_BAD;

	if (ctx->current_state == OP_INIT ||
	    ctx->current_state == OP_ONE_SHOT) {
		if (!ctx->tag) {
			ctx->tag = calloc(1, taglen);
			if (!ctx->tag)
				return CKR_HOST_MEMORY;

			ctx->tag_length = taglen;
		}
	}

	if (op_flag & (CKF_DECRYPT | CKF_MESSAGE_DECRYPT)) {
		if (!ctx->tag || ctx->tag_length != taglen)
			return CKR_MECHANISM_PARAM_INVALID;

		memcpy(ctx->tag, tag, taglen);
	}

	return CKR_OK;
}

/**
 * check_cipher_params() -  Check cipher parameters
 * @mechanism: Mechanism type
 * @pparameter: Pointer to mechanism parameter
 * @ulparameterlen: Mechanism parameter length
 * @op_flag: Operation flag
 * @ctx: Pointer to cipher context
 *
 * Store cipher context parameters IV and IV length, if valid.
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - @pmechanism parameters are invalid
 * CKR_MECHANISM_INVALID              - @pmechanism.mechanism is invalid
 * CKR_OK                             - Success
 */
static CK_RV check_cipher_params(CK_MECHANISM_TYPE mechanism,
				 CK_VOID_PTR pparameter,
				 CK_ULONG ulparameterlen, CK_FLAGS op_flag,
				 struct lib_cipher_ctx *ctx)
{
	CK_RV ret = CKR_OK;
	CK_ULONG bytes = 0;
	CK_AES_CTR_PARAMS_PTR aes_ctr_params = NULL_PTR;
	CK_SM4_CTR_PARAMS_PTR sm4_ctr_params = NULL_PTR;

	CK_GCM_PARAMS_PTR gcm_prms = NULL_PTR;
	CK_CCM_PARAMS_PTR ccm_prms = NULL_PTR;
	CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR chacha_prms = NULL_PTR;

	CK_GCM_MESSAGE_PARAMS_PTR gcm_msg_prms = NULL_PTR;
	CK_CCM_MESSAGE_PARAMS_PTR ccm_msg_prms = NULL_PTR;
	CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_PTR chacha_msg_prms = NULL_PTR;

	switch (mechanism) {
	case CKM_AES_CBC:
		if (!pparameter) {
			DBG_TRACE("CBC mode: IV is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (ulparameterlen != AES_IV_LEN) {
			DBG_TRACE("CBC mode: IV length is not correct");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ret = set_iv_value(pparameter, ulparameterlen, ctx);
		break;

	case CKM_DES_CBC:
	case CKM_DES3_CBC:
		if (!pparameter) {
			DBG_TRACE("CBC mode: IV is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (ulparameterlen != DES_IV_LEN) {
			DBG_TRACE("CBC mode: IV length is not correct");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ret = set_iv_value(pparameter, ulparameterlen, ctx);
		break;

	case CKM_AES_CTR:
		if (!pparameter) {
			DBG_TRACE("CTR mode: Counter Bits is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (ulparameterlen != sizeof(CK_AES_CTR_PARAMS)) {
			DBG_TRACE("ulParameterLen error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		aes_ctr_params = (CK_AES_CTR_PARAMS_PTR)pparameter;

		if (aes_ctr_params->ulCounterBits > MAX_COUNTER_BITS) {
			DBG_TRACE("ulCounterBits error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ret = set_iv_value(aes_ctr_params->cb,
				   sizeof(aes_ctr_params->cb), ctx);
		break;

	case CKM_AES_CTS:
		if (!pparameter) {
			DBG_TRACE("CTS mode: IV is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ret = set_iv_value(pparameter, ulparameterlen, ctx);
		break;

	case CKM_AES_XTS:
		if (!pparameter) {
			DBG_TRACE("XTS mode: IV is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ret = set_iv_value(pparameter, ulparameterlen, ctx);
		break;

	case CKM_AES_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_SM4_ECB:
		break;

	case CKM_SM4_CBC:
		if (!pparameter) {
			DBG_TRACE("SM4 CBC mode: IV is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (ulparameterlen != SM4_IV_LEN) {
			DBG_TRACE("SM4 CBC mode: IV length is not correct");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ret = set_iv_value(pparameter, ulparameterlen, ctx);
		break;

	case CKM_SM4_CTR:
		if (!pparameter) {
			DBG_TRACE("SM4 CTR mode: Counter bits is not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (ulparameterlen != sizeof(CK_SM4_CTR_PARAMS)) {
			DBG_TRACE("ulParameterLen error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		sm4_ctr_params = (CK_SM4_CTR_PARAMS_PTR)pparameter;

		if (sm4_ctr_params->ulCounterBits > MAX_COUNTER_BITS) {
			DBG_TRACE("ulCounterBits error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ret = set_iv_value(sm4_ctr_params->cb,
				   sizeof(sm4_ctr_params->cb), ctx);
		break;

	case CKM_AES_GCM:
		if (!pparameter) {
			DBG_TRACE("GCM mode: Parameters not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (op_flag & (CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT)) {
			if (ulparameterlen != sizeof(CK_GCM_MESSAGE_PARAMS)) {
				DBG_TRACE("ulParameterLen error");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			gcm_msg_prms = (CK_GCM_MESSAGE_PARAMS_PTR)pparameter;

			bytes = BITS_TO_BYTES_SIZE(gcm_msg_prms->ulTagBits);
			ret = set_tag_value(gcm_msg_prms->pTag, bytes, op_flag,
					    ctx);
			if (ret)
				break;

			ret = set_iv_value(gcm_msg_prms->pIv,
					   gcm_msg_prms->ulIvLen, ctx);
			if (ret)
				break;

			bytes = BITS_TO_BYTES_SIZE(gcm_msg_prms->ulIvFixedBits);

			switch (gcm_msg_prms->ivGenerator) {
			case CKG_NO_GENERATE:
				break;
			case CKG_GENERATE:
			case CKG_GENERATE_RANDOM:
			case CKG_GENERATE_COUNTER:
				if (op_flag != CKF_MESSAGE_ENCRYPT)
					return CKR_MECHANISM_PARAM_INVALID;

				ctx->fixed_iv_length = bytes;
				break;
			default:
				ret = CKR_FUNCTION_NOT_SUPPORTED;
				break;
			}
		} else {
			if (ulparameterlen != sizeof(CK_GCM_PARAMS)) {
				DBG_TRACE("ulParameterLen error");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			gcm_prms = (CK_GCM_PARAMS_PTR)pparameter;

			ret = set_iv_value(gcm_prms->pIv, gcm_prms->ulIvLen,
					   ctx);
			if (ret)
				break;

			ctx->aad = gcm_prms->pAAD;
			ctx->aad_length = gcm_prms->ulAADLen;
			ctx->tag_length =
				BITS_TO_BYTES_SIZE(gcm_prms->ulTagBits);
		}

		break;

	case CKM_AES_CCM:
		if (!pparameter) {
			DBG_TRACE("CCM mode: Parameters not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (op_flag & (CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT)) {
			if (ulparameterlen != sizeof(CK_CCM_MESSAGE_PARAMS)) {
				DBG_TRACE("ulParameterLen error");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			ccm_msg_prms = (CK_CCM_MESSAGE_PARAMS_PTR)pparameter;

			ctx->payload_length = ccm_msg_prms->ulDataLen;

			ret = set_tag_value(ccm_msg_prms->pMAC,
					    ccm_msg_prms->ulMACLen, op_flag,
					    ctx);
			if (ret)
				break;

			ret = set_iv_value(ccm_msg_prms->pNonce,
					   ccm_msg_prms->ulNonceLen, ctx);
		} else {
			if (ulparameterlen != sizeof(CK_CCM_PARAMS)) {
				DBG_TRACE("ulParameterLen error");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			ccm_prms = (CK_CCM_PARAMS_PTR)pparameter;

			set_iv_value(ccm_prms->pNonce, ccm_prms->ulNonceLen,
				     ctx);
			ctx->aad = ccm_prms->pAAD;
			ctx->aad_length = ccm_prms->ulAADLen;
			ctx->tag_length = ccm_prms->ulMACLen;
		}

		break;

	case CKM_CHACHA20_POLY1305:
		if (!pparameter) {
			DBG_TRACE("ChaCha20-Poly1305 mode: Parameters not set");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		if (op_flag & (CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT)) {
			if (ulparameterlen !=
			    sizeof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)) {
				DBG_TRACE("ulParameterLen error");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			chacha_msg_prms =
				(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_PTR)
					pparameter;

			ctx->payload_length = 0;

			ret = set_tag_value(chacha_msg_prms->pTag, 16, op_flag,
					    ctx);
			if (ret)
				break;

			bytes = BITS_TO_BYTES_SIZE(chacha_msg_prms->ulNonceLen);
			ret = set_iv_value(chacha_msg_prms->pNonce, bytes, ctx);
		} else {
			if (ulparameterlen !=
			    sizeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS)) {
				DBG_TRACE("ulParameterLen error");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			chacha_prms = (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR)
				pparameter;

			set_iv_value(chacha_prms->pNonce,
				     chacha_prms->ulNonceLen, ctx);
			ctx->aad = chacha_prms->pAAD;
			ctx->aad_length = chacha_prms->ulAADLen;
			ctx->tag_length = 16;
		}

		break;

	default:
		ret = CKR_MECHANISM_INVALID;
	}

	return ret;
}

/**
 * check_cipher_mech_params() -  Check cipher mechanism parameters
 * @pmechanism: Pointer to mechanism
 * @op_flag: Operation flag
 * @ctx: Pointer to cipher context
 *
 * Store cipher context parameters IV and IV length, if valid.
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - @pmechanism parameters are invalid
 * CKR_MECHANISM_INVALID              - @pmechanism.mechanism is invalid
 * CKR_OK                             - Success
 */
static CK_RV check_cipher_mech_params(CK_MECHANISM_PTR pmechanism,
				      CK_FLAGS op_flag,
				      struct lib_cipher_ctx *ctx)
{
	return check_cipher_params(pmechanism->mechanism,
				   pmechanism->pParameter,
				   pmechanism->ulParameterLen, op_flag, ctx);
}

/**
 * update_params() -  Update aead parameters
 * @mechanism: Mechanism type
 * @pparameter: Pointer to mechanism parameter
 * @ulparameterlen: Mechanism parameter length
 * @ctx: Pointer to aead context
 *
 * Load aead context parameters IV and IV length, Tag and Tag length if valid.
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - @pmechanism parameters are invalid
 * CKR_MECHANISM_INVALID              - @pmechanism.mechanism is invalid
 * CKR_OK                             - Success
 */
static CK_RV update_params(CK_MECHANISM_TYPE mechanism, CK_VOID_PTR pparameter,
			   CK_ULONG ulparameterlen, struct lib_cipher_ctx *ctx)
{
	CK_GCM_MESSAGE_PARAMS_PTR gcm_prms = NULL_PTR;
	CK_CCM_MESSAGE_PARAMS_PTR ccm_prms = NULL_PTR;
	CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_PTR chacha_prms = NULL_PTR;

	if (!pparameter)
		return CKR_OK;

	switch (mechanism) {
	case CKM_AES_GCM:
		if (ulparameterlen != sizeof(CK_GCM_MESSAGE_PARAMS)) {
			DBG_TRACE("ulParameterLen error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		gcm_prms = (CK_GCM_MESSAGE_PARAMS_PTR)pparameter;

		if (ctx->iv_length && ctx->iv_length <= gcm_prms->ulIvLen) {
			gcm_prms->ulIvLen = ctx->iv_length;
			memcpy(gcm_prms->pIv, ctx->iv, ctx->iv_length);
		}

		if (MUL_OVERFLOW(ctx->tag_length, 8, &gcm_prms->ulTagBits))
			return CKR_MECHANISM_PARAM_INVALID;

		memcpy(gcm_prms->pTag, ctx->tag, ctx->tag_length);

		break;

	case CKM_AES_CCM:
		if (ulparameterlen != sizeof(CK_CCM_MESSAGE_PARAMS)) {
			DBG_TRACE("ulParameterLen error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		ccm_prms = (CK_CCM_MESSAGE_PARAMS_PTR)pparameter;

		ccm_prms->ulNonceLen = ctx->iv_length;
		ccm_prms->ulMACLen = ctx->tag_length;

		memcpy(ccm_prms->pMAC, ctx->tag, ctx->tag_length);
		break;

	case CKM_CHACHA20_POLY1305:
		if (ulparameterlen !=
		    sizeof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)) {
			DBG_TRACE("ulParameterLen error");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		chacha_prms =
			(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_PTR)pparameter;

		chacha_prms->ulNonceLen = BYTES_TO_BITS(ctx->iv_length);
		memcpy(chacha_prms->pNonce, ctx->iv, ctx->iv_length);

		memcpy(chacha_prms->pTag, ctx->tag, 16);
		break;

	default:
		break;
	}

	return CKR_OK;
}

/**
 * set_key_value() - Sets key buffer value and key length
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
 * tls_update_buffers() -  Update aead input and output buffers for TLS cipher
 *                         operation.
 * @params: Cipher parameters
 * @ctx: Pointer to aead context
 *
 * Update aead context parameters input and input length, output and output
 * length if valid.
 * This is a workaround for TLS record encrypt/decryption operation.
 *
 * Return:
 * CKR_HOST_MEMORY                     - Memory allocation error
 * CKR_ARGUMENTS_BAD                   - Bad arguments
 * CKR_OK                              - Success
 */
static CK_RV tls_update_buffers(struct lib_cipher_params *params,
				struct lib_cipher_ctx *ctx)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	CK_BYTE_PTR input = NULL;
	CK_ULONG input_len = 0;

	struct libobj_obj *obj = NULL;

	if (!ctx || !params)
		goto end;

	obj = (struct libobj_obj *)ctx->hkey;
	if (get_key_tls(obj) == NOT_TLS_KEY)
		return CKR_OK;

	if (!params->poutput)
		return CKR_OK;

	if (params->state == OP_UPDATE) {
		if (ctx->input) {
			if (ADD_OVERFLOW(ctx->input_length,
					 params->input_length, &input_len))
				goto end;

			input = realloc(ctx->input, input_len);
		} else {
			input_len = params->input_length;
			input = malloc(input_len);
		}

		if (!input) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		ctx->input = input;
		input = input + ctx->input_length;
		memcpy(input, params->pinput, params->input_length);
		ctx->input_length = input_len;

		if (!ctx->output) {
			ctx->output = params->poutput;
			ctx->output_length = params->output_length;
		} else if (ctx->output + ctx->output_length ==
			   params->poutput) {
			if (ADD_OVERFLOW(ctx->output_length,
					 params->output_length,
					 &ctx->output_length))
				goto end;
		} else {
			/* Support only one contiguous output buffer */
			goto end;
		}
	} else if (params->state == OP_FINAL) {
		/* Support only one contiguous output buffer */
		if (ctx->output + ctx->output_length != params->poutput)
			goto end;

		if (params->op_flag & CKF_ENCRYPT) {
			/* Get tag value if none was set in parameters  */
			if (!ctx->tag) {
				ctx->tag = calloc(1, ctx->tag_length);
				if (!ctx->tag) {
					ret = CKR_HOST_MEMORY;
					goto end;
				}
			}

			if (ADD_OVERFLOW(ctx->output_length,
					 params->output_length,
					 &ctx->output_length))
				goto end;
		}
	}

	ret = CKR_OK;

end:
	return ret;
}

CK_RV lib_cipher_cancel_operation(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;

	struct lib_cipher_ctx *ctx = NULL;

	CK_MECHANISM mechanism = { 0 };

	ret = libsess_find_opctx(hsession, op_flag, &mechanism, (void **)&ctx);
	if (ret != CKR_OK)
		return ret;

	if (!ctx) {
		ret = libsess_remove_opctx(hsession, op_flag);
		return ret;
	}

	switch (ctx->current_state) {
	case OP_INIT:
	case OP_ONE_SHOT:
	case OP_BEGIN:
	case OP_END:
		ret = libsess_remove_opctx(hsession, op_flag);
		break;

	case OP_UPDATE:
	case OP_NEXT:
	case OP_FINAL:
		if (ctx->context)
			ret = libsess_cancel_opctx(hsession, op_flag,
						   (void **)&ctx->context);
		else
			ret = libsess_remove_opctx(hsession, op_flag);

		break;

	default:
		break;
	}

	destroy_context(ctx);

	return ret;
}

CK_RV lib_cipher_copy_operation(void *src, void **dst)
{
	CK_RV ret = CKR_OK;
	struct lib_cipher_ctx *src_ctx = src;
	struct lib_cipher_ctx *dst_ctx = NULL;

	dst_ctx = calloc(1, sizeof(struct lib_cipher_ctx));
	if (!dst_ctx)
		return CKR_HOST_MEMORY;

	memcpy(dst_ctx, src_ctx, sizeof(*dst_ctx));

	dst_ctx->key_value = NULL_PTR;
	dst_ctx->iv = NULL_PTR;
	dst_ctx->tag = NULL_PTR;
	dst_ctx->context = NULL;

	ret = libdev_copy_operation(src_ctx->context, &dst_ctx->context);
	if (ret != CKR_OK)
		goto end;

	*dst = dst_ctx;

end:
	if (ret != CKR_OK) {
		if (dst_ctx->context)
			free(dst_ctx->context);

		free(dst_ctx);
	}

	return ret;
}

CK_RV lib_encrypt_decrypt_init(CK_SESSION_HANDLE hsession,
			       CK_MECHANISM_PTR pmechanism,
			       CK_OBJECT_HANDLE hkey, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	struct lib_cipher_ctx *ctx = NULL;
	CK_BBOOL key_op = CK_FALSE;
	CK_ATTRIBUTE iskey_op[] = {
		{ CKA_DECRYPT, &key_op, sizeof(key_op) },
	};

	DBG_TRACE("Initialize %s operation",
		  op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT) ? "Encrypt" :
								  "Decrypt");

	if (!pmechanism) {
		/*
		 * Check if any multi-part cipher operation is active.
		 * If a multi-part operation is active, cancel the operation
		 * and remove the operation context.
		 */
		ret = lib_cipher_cancel_operation(hsession, op_flag);
		if (ret == CKR_OPERATION_NOT_INITIALIZED)
			ret = CKR_OK;

		return ret;
	}

	/* Validate mechanism operation flag */
	ret = libsess_validate_mechanism(hsession, pmechanism, op_flag);
	if (ret != CKR_OK)
		goto end;

	if (op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
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
	ctx->context = NULL;
	/* Set the current state */
	ctx->current_state = OP_INIT;

	ret = check_cipher_mech_params(pmechanism, op_flag, ctx);
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
	if (ret != CKR_OK)
		destroy_context(ctx);

	return ret;
}

CK_RV lib_encrypt_decrypt_reset(CK_SESSION_HANDLE hsession,
				CK_VOID_PTR pparameter, CK_ULONG ulparameterlen,
				CK_BYTE_PTR pAssociatedData,
				CK_ULONG ulAssociatedDataLen, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	CK_MECHANISM mechanism = { 0 };
	struct lib_cipher_ctx *ctx = NULL;

	if (!pparameter != !ulparameterlen)
		return CKR_MECHANISM_PARAM_INVALID;

	/* Check that operation is initialized */
	ret = libsess_find_opctx(hsession, op_flag, &mechanism, (void **)&ctx);
	if (ret != CKR_OK)
		return ret;

	if (ctx->current_state != OP_END && ctx->context)
		return CKR_OPERATION_ACTIVE;

	/* Update mechanism parameter */
	if (pparameter) {
		ret = check_cipher_params(mechanism.mechanism, pparameter,
					  ulparameterlen, op_flag, ctx);
		if (ret != CKR_OK)
			return ret;
	}

	ctx->current_state = OP_BEGIN;

	if (!pAssociatedData == !ulAssociatedDataLen) {
		ctx->aad = pAssociatedData;
		ctx->aad_length = ulAssociatedDataLen;
	}

	return ret;
}

CK_RV lib_encrypt_decrypt(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
			  CK_ULONG ulparameterlen, CK_BYTE_PTR pAssociatedData,
			  CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pinput,
			  CK_ULONG input_length, CK_BYTE_PTR poutput,
			  CK_ULONG_PTR poutput_length, CK_FLAGS op_flag,
			  enum op_state state)
{
	CK_RV ret = CKR_OK;
	CK_MECHANISM mechanism = { 0 };
	struct lib_cipher_ctx *ctx = NULL;
	struct lib_cipher_params params = { 0 };
	struct libobj_obj *obj = NULL;
	CK_BBOOL terminate = CK_TRUE;

	if (state == OP_ONE_SHOT || state == OP_UPDATE || state == OP_NEXT) {
		if (!input_length) {
			ret = (op_flag & (CKF_MESSAGE_ENCRYPT | CKF_ENCRYPT)) ?
				      CKR_DATA_LEN_RANGE :
				      CKR_ENCRYPTED_DATA_LEN_RANGE;
			goto end;
		}

		if (!pinput) {
			ret = (op_flag & (CKF_MESSAGE_ENCRYPT | CKF_ENCRYPT)) ?
				      CKR_DATA_INVALID :
				      CKR_ENCRYPTED_DATA_INVALID;
			goto end;
		}
	}

	if (!poutput_length) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (!pparameter != !ulparameterlen) {
		ret = CKR_MECHANISM_PARAM_INVALID;
		goto end;
	}

	/* Check that operation is initialized */
	ret = libsess_find_opctx(hsession, op_flag, &mechanism, (void **)&ctx);
	if (ret != CKR_OK)
		goto end;

	ret = libopctx_check_next_state(ctx->current_state, state, &terminate);
	if (ret != CKR_OK)
		goto end;

	params.op_flag = op_flag;
	params.ctx = ctx;
	params.pinput = pinput;
	params.input_length = input_length;
	params.poutput = poutput;
	params.output_length = *poutput_length;
	params.state = state;

	/* Update mechanism parameter */
	if (pparameter) {
		ret = check_cipher_params(mechanism.mechanism, pparameter,
					  ulparameterlen, op_flag, ctx);
		if (ret != CKR_OK)
			goto end;
	}

	/* Only update aad for message-based encryption/decryption */
	if (op_flag & (CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT)) {
		if (!pAssociatedData == !ulAssociatedDataLen) {
			ctx->aad = pAssociatedData;
			ctx->aad_length = ulAssociatedDataLen;
		}
	}

	if (op_flag & CKF_ENCRYPT)
		ctx->payload_length = params.input_length;
	else if ((op_flag & CKF_DECRYPT) &&
		 (state == OP_ONE_SHOT || state == OP_UPDATE ||
		  state == OP_NEXT))
		if (SUB_OVERFLOW(params.input_length, ctx->tag_length,
				 &ctx->payload_length)) {
			ret = CKR_DATA_LEN_RANGE;
			goto end;
		}

	ret = tls_update_buffers(&params, ctx);
	if (ret != CKR_OK)
		goto end;

	/* Run operation */
	ret = libdev_operate_mechanism(hsession, &mechanism, &params);
	if (ret != CKR_BUFFER_TOO_SMALL && ret != CKR_OK)
		goto end;

	/* Update output data buffer length */
	obj = (struct libobj_obj *)ctx->hkey;
	if ((get_key_tls(obj) == NOT_TLS_KEY) || !poutput)
		*poutput_length = params.output_length;

	if (ret == CKR_BUFFER_TOO_SMALL && !poutput)
		ret = CKR_OK;

	if (ret == CKR_OK) {
		ctx->current_state = state;

		if (op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT) &&
		    (state == OP_ONE_SHOT || state == OP_FINAL ||
		     state == OP_END)) {
			ret = update_params(mechanism.mechanism, pparameter,
					    ulparameterlen, ctx);
			if (ret != CKR_OK)
				goto end;
		}

		if (poutput && (state == OP_ONE_SHOT || state == OP_FINAL))
			goto end;
	}

	terminate = CK_FALSE;

end:
	if (!terminate)
		return ret;

	/*
	 * Cancel the on-going multipart operation and
	 * remove operation context.
	 */
	(void)lib_cipher_cancel_operation(hsession, op_flag);

	return ret;
}
