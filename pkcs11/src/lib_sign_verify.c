// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "lib_sign_verify.h"
#include "lib_device.h"
#include "lib_session.h"
#include "lib_object.h"

#include "util.h"
#include "trace.h"

/**
 * destroy_context() - Destroy signature context
 * @ctx: Pointer to cipher context
 *
 */
static void destroy_context(struct lib_signature_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->type == SIGN_TYPE_EDDSA) {
		if (ctx->sign.eddsa.context_data)
			free(ctx->sign.eddsa.context_data);
	}

	free(ctx);
}

/**
 * is_rsa_pss_mechanism() - Check if mechanism type is RSA PKCS PSS
 * @type: Mechanism type
 *
 * Return:
 * True if RSA PKCS PSS mechanism
 * False otherwise
 */
static CK_BBOOL is_rsa_pss_mechanism(CK_MECHANISM_TYPE type)
{
	switch (type) {
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
		return CK_TRUE;

	default:
		return CK_FALSE;
	}
}

/**
 * is_tls_mac_mechanism() - Check if mechanism type is TLS MAC
 * @type: Mechanism type
 *
 * Return:
 * True if TLS MAC mechanism
 * False otherwise
 */
static CK_BBOOL is_tls_mac_mechanism(CK_MECHANISM_TYPE type)
{
	return (type == CKM_TLS_MAC) ? CK_TRUE : CK_FALSE;
}

/**
 * is_rsa_pkcs_mechanism() - Check if mechanism type is RSA PKCS
 * @type: Mechanism type
 *
 * Return:
 * True if RSA PKCS mechanism
 * False otherwise
 */
static CK_BBOOL is_rsa_pkcs_mechanism(CK_MECHANISM_TYPE type)
{
	switch (type) {
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_SHA3_224_RSA_PKCS:
	case CKM_SHA3_256_RSA_PKCS:
	case CKM_SHA3_384_RSA_PKCS:
	case CKM_SHA3_512_RSA_PKCS:
		return CK_TRUE;

	default:
		return CK_FALSE;
	}
}

/**
 * get_hash_mech_from_rsa_pss_mech() - Get hash mechanism from RSA PSS mechanism
 * @sign_mech: RSA PSS signature mechanism
 *
 * Return:
 * Hash mechanism
 * 0 otherwise
 */
static CK_MECHANISM_TYPE
get_hash_mech_from_rsa_pss_mech(CK_MECHANISM_TYPE sign_mech)
{
	switch (sign_mech) {
	case CKM_SHA1_RSA_PKCS_PSS:
		return CKM_SHA_1;

	case CKM_SHA224_RSA_PKCS_PSS:
		return CKM_SHA224;

	case CKM_SHA256_RSA_PKCS_PSS:
		return CKM_SHA256;

	case CKM_SHA384_RSA_PKCS_PSS:
		return CKM_SHA384;

	case CKM_SHA512_RSA_PKCS_PSS:
		return CKM_SHA512;

	default:
		return 0;
	}
}

/**
 * get_hash_mech_from_mgf() - Get hash mechanism from MGF type
 * @mgf: MGF type
 * @hash_mech: Pointer to hash mechanism to update
 *
 * If @mgf is invalid, @hash_mech is set to 0
 *
 * Return:
 * CKR_MECHANISM_INVALID        - @mgf is invalid
 * CKR_OK                       - Success
 */
static CK_RV get_hash_mech_from_mgf(CK_RSA_PKCS_MGF_TYPE mgf,
				    CK_MECHANISM_TYPE_PTR hash_mech)
{
	switch (mgf) {
	case CKG_MGF1_SHA1:
		*hash_mech = CKM_SHA_1;
		return CKR_OK;

	case CKG_MGF1_SHA224:
		*hash_mech = CKM_SHA224;
		return CKR_OK;

	case CKG_MGF1_SHA256:
		*hash_mech = CKM_SHA256;
		return CKR_OK;

	case CKG_MGF1_SHA384:
		*hash_mech = CKM_SHA384;
		return CKR_OK;

	case CKG_MGF1_SHA512:
		*hash_mech = CKM_SHA512;
		return CKR_OK;

	default:
		*hash_mech = 0;
		return CKR_MECHANISM_INVALID;
	}
}

/**
 * check_rsa_pss() - Check RSA PSS mechanism parameters
 * @mechanism: Mechanism type
 * @pparameter: Pointer to mechanism parameter
 * @ulparameterlen: Mechanism parameter length
 * @ctx: Pointer to signature context
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - Mechanism parameters invalid
 * CKR_OK                             - Success
 */
static CK_RV check_rsa_pss(CK_MECHANISM_TYPE mechanism, CK_VOID_PTR pparameter,
			   CK_ULONG ulparameterlen,
			   struct lib_signature_ctx *ctx)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;
	CK_MECHANISM_TYPE mech_hash = 0;
	CK_MECHANISM_TYPE mgf_hash = 0;
	CK_RSA_PKCS_PSS_PARAMS_PTR mech_params = NULL_PTR;

	DBG_TRACE("Check RSA PSS signature mechanism parameter");

	if (!pparameter)
		return CKR_OK;

	if (ulparameterlen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
		return ret;

	/* Get hash mechanism from mechanism type */
	mech_hash = get_hash_mech_from_rsa_pss_mech(mechanism);

	mech_params = (CK_RSA_PKCS_PSS_PARAMS_PTR)pparameter;

	if (mech_params->hashAlg) {
		/*
		 * Compare hash algorithm set in the parameter structure with
		 * the one set by the mechanism type
		 */
		if (mech_hash && mech_hash != mech_params->hashAlg)
			return CKR_MECHANISM_PARAM_INVALID;

		mech_hash = mech_params->hashAlg;
	}

	if (mech_params->mgf) {
		ret = get_hash_mech_from_mgf(mech_params->mgf, &mgf_hash);
		if (ret != CKR_OK)
			return CKR_MECHANISM_PARAM_INVALID;

		/*
		 * Compare Mask Generation Function hash algorithm with the one
		 * set by mechanism parameter or mechanism type
		 */
		if (mech_hash && mech_hash != mgf_hash)
			return CKR_MECHANISM_PARAM_INVALID;

		mech_hash = mech_params->mgf;
	}

	/* Set context with mechanism parameters */
	ctx->hash_mech = mech_hash;

	ctx->type = SIGN_TYPE_RSA;

	if (mech_params->sLen)
		ctx->sign.rsa.salt_len = mech_params->sLen;

	return CKR_OK;
}

/**
 * check_tls_mac() - Check TLS MAC mechanism parameters
 * @pparameter: Pointer to mechanism parameter
 * @ulparameterlen: Mechanism parameter length
 * @ctx: Pointer to signature context
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - Mechanism parameters invalid
 * CKR_OK                             - Success
 */
static CK_RV check_tls_mac(CK_VOID_PTR pparameter, CK_ULONG ulparameterlen,
			   struct lib_signature_ctx *ctx)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;
	CK_TLS_MAC_PARAMS_PTR mech_params = NULL_PTR;

	DBG_TRACE("Check TLS signature mechanism parameter");

	if (ulparameterlen != sizeof(CK_TLS_MAC_PARAMS))
		return ret;

	mech_params = (CK_TLS_MAC_PARAMS_PTR)pparameter;

	/* Set context with mechanism parameters */
	ctx->hash_mech = mech_params->prfHashMechanism;
	ctx->sign.tls12.mac_len = mech_params->ulMacLength;
	ctx->sign.tls12.server_client = mech_params->ulServerOrClient;

	return CKR_OK;
}

/**
 * is_general_length_mac_mechanism() - Check if mechanism type is
 *                                     general-length CMAC/HMAC
 * @mechanism: Mechanism type
 *
 * Return:
 * True if CMAC/HMAC mechanism
 * False otherwise
 */
static CK_BBOOL is_general_length_mac_mechanism(CK_MECHANISM_TYPE mechanism)
{
	switch (mechanism) {
	case CKM_AES_CMAC_GENERAL:
	case CKM_DES3_CMAC_GENERAL:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA224_HMAC_GENERAL:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA3_256_HMAC_GENERAL:
	case CKM_SHA3_224_HMAC_GENERAL:
	case CKM_SHA3_384_HMAC_GENERAL:
	case CKM_SHA3_512_HMAC_GENERAL:
		return CK_TRUE;

	default:
		return CK_FALSE;
	}
}

/**
 * is_mac_mechanism() - Check if mechanism type is CMAC/HMAC
 * @mechanism: Mechanism type
 *
 * Return:
 * True if CMAC/HMAC mechanism
 * False otherwise
 */
static CK_BBOOL is_mac_mechanism(CK_MECHANISM_TYPE mechanism)
{
	switch (mechanism) {
	case CKM_AES_CMAC:
	case CKM_DES3_CMAC:
	case CKM_MD2_HMAC:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA224_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_SHA3_256_HMAC:
	case CKM_SHA3_224_HMAC:
	case CKM_SHA3_384_HMAC:
	case CKM_SHA3_512_HMAC:
		return CK_TRUE;

	default:
		return CK_FALSE;
	}
}

/**
 * check_mac() - Check MAC mechanism parameters
 * @pparameter: Pointer to mechanism parameter
 * @ulparameterlen: Mechanism parameter length
 * @ctx: Pointer to signature context
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - Mechanism parameters invalid
 * CKR_OK                             - Success
 */
static CK_RV check_mac(CK_VOID_PTR pparameter, CK_ULONG ulparameterlen,
		       struct lib_signature_ctx *ctx)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;
	CK_MAC_GENERAL_PARAMS_PTR mech_params = NULL_PTR;

	DBG_TRACE("Check MAC signature mechanism parameter");

	if (!pparameter)
		return CKR_OK;

	if (ulparameterlen != sizeof(CK_MAC_GENERAL_PARAMS))
		return ret;

	mech_params = (CK_MAC_GENERAL_PARAMS_PTR)pparameter;

	if (!*mech_params)
		return ret;

	/* Set context with mechanism parameters */
	ctx->type = SIGN_TYPE_MAC;
	ctx->sign.mac.len = *mech_params;

	return CKR_OK;
}

/**
 * is_eddsa_mechanism() - Check if mechanism type is EDDSA
 * @type: Mechanism type
 *
 * Return:
 * True if EDDSA mechanism
 * False otherwise
 */
static CK_BBOOL is_eddsa_mechanism(CK_MECHANISM_TYPE type)
{
	switch (type) {
	case CKM_EDDSA:
		return CK_TRUE;

	default:
		return CK_FALSE;
	}
}

/**
 * is_ecdsa_mechanism() - Check if mechanism type is ECDSA
 * @type: Mechanism type
 *
 * Return:
 * True if ECDSA mechanism
 * False otherwise
 */
static CK_BBOOL is_ecdsa_mechanism(CK_MECHANISM_TYPE type)
{
	switch (type) {
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		return CK_TRUE;

	default:
		return CK_FALSE;
	}
}

/**
 * check_eddsa() - Check EDDSA mechanism parameters
 * @pparameter: Pointer to mechanism parameter
 * @ulparameterlen: Mechanism parameter length
 * @ctx: Pointer to signature context
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - Mechanism parameters invalid
 * CKR_OK                             - Success
 */
static CK_RV check_eddsa(CK_VOID_PTR pparameter, CK_ULONG ulparameterlen,
			 struct lib_signature_ctx *ctx)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;
	CK_EDDSA_PARAMS_PTR mech_params = pparameter;

	DBG_TRACE("Check EDDSA signature mechanism parameter");

	ctx->hash_mech = 0;

	if (!pparameter)
		return CKR_OK;

	if (ulparameterlen != sizeof(CK_EDDSA_PARAMS))
		goto end;

	if (mech_params && mech_params->pContextData) {
		if (!mech_params->ulContextDataLen ||
		    mech_params->ulContextDataLen > 255)
			goto end;
	}

	ctx->type = SIGN_TYPE_EDDSA;

	if (mech_params) {
		ctx->sign.eddsa.prehashed = mech_params->phFlag;

		if (!mech_params->ulContextDataLen) {
			ret = CKR_OK;
			goto end;
		}

		if (!mech_params->pContextData) {
			ret = CKR_MECHANISM_PARAM_INVALID;
			goto end;
		}

		/* Context already defined */
		if (ctx->sign.eddsa.context_data) {
			ret = CKR_OK;
			goto end;
		}

		ctx->sign.eddsa.context_len = mech_params->ulContextDataLen;
		ctx->sign.eddsa.context_data =
			malloc(ctx->sign.eddsa.context_len);
		if (!ctx->sign.eddsa.context_data) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		memcpy(ctx->sign.eddsa.context_data, mech_params->pContextData,
		       ctx->sign.eddsa.context_len);
	}

	ret = CKR_OK;

end:
	return ret;
}

/**
 * check_signature_params() -  Check signature parameters
 * @mechanism: Mechanism type
 * @pparameter: Pointer to mechanism parameter
 * @ulparameterlen: Mechanism parameter length
 * @op_flag: Operation flag
 * @ctx: Pointer to signature context
 *
 * Store signature context parameters, if valid.
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - @pparameter is invalid
 * CKR_MECHANISM_INVALID              - @mechanism is invalid
 * CKR_OK                             - Success
 */
static CK_RV check_signature_params(CK_MECHANISM_TYPE mechanism,
				    CK_VOID_PTR pparameter,
				    CK_ULONG ulparameterlen,
				    struct lib_signature_ctx *ctx)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;

	DBG_TRACE("Check signature mechanism parameter");

	if (!pparameter != !ulparameterlen)
		return ret;

	if (is_tls_mac_mechanism(mechanism)) {
		ctx->type = SIGN_TYPE_TLS12;
		ret = check_tls_mac(pparameter, ulparameterlen, ctx);
	} else if (is_rsa_pss_mechanism(mechanism)) {
		ctx->type = SIGN_TYPE_RSA;
		ret = check_rsa_pss(mechanism, pparameter, ulparameterlen, ctx);
	} else if (is_rsa_pkcs_mechanism(mechanism)) {
		ctx->type = SIGN_TYPE_RSA;
		ret = CKR_OK;
	} else if (is_general_length_mac_mechanism(mechanism)) {
		ctx->type = SIGN_TYPE_MAC;
		ret = check_mac(pparameter, ulparameterlen, ctx);
	} else if (is_mac_mechanism(mechanism)) {
		ctx->type = SIGN_TYPE_MAC;
		ret = CKR_OK;
	} else if (is_eddsa_mechanism(mechanism)) {
		ctx->type = SIGN_TYPE_EDDSA;
		ret = check_eddsa(pparameter, ulparameterlen, ctx);
	} else if (is_ecdsa_mechanism(mechanism)) {
		ctx->type = SIGN_TYPE_ECDSA;
		ret = CKR_OK;
	}

	return ret;
}

/**
 * check_signature_mech_params() - Check signature mechanism parameters
 * @pmechanism: Pointer to mechanism
 * @ctx: Pointer to signature context
 *
 * Store signature context parameters, if valid.
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - @pmechanism parameters are invalid
 * CKR_OK                             - Success
 */
static CK_RV check_signature_mech_params(CK_MECHANISM_PTR pmechanism,
					 struct lib_signature_ctx *ctx)
{
	return check_signature_params(pmechanism->mechanism,
				      pmechanism->pParameter,
				      pmechanism->ulParameterLen, ctx);
}

CK_RV lib_sign_verify_cancel_operation(CK_SESSION_HANDLE hsession,
				       CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;

	struct lib_signature_ctx *ctx = NULL;

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

CK_RV lib_sign_verify_init(CK_SESSION_HANDLE hsession,
			   CK_MECHANISM_PTR pmechanism, CK_OBJECT_HANDLE hkey,
			   CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	struct lib_signature_ctx *ctx = NULL;
	CK_BBOOL key_op = CK_FALSE;
	CK_ATTRIBUTE iskey_op[] = {
		{ CKA_VERIFY, &key_op, sizeof(key_op) },
	};

	DBG_TRACE("Initialize %s operation",
		  op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN) ? "Sign" : "Verify");

	if (!pmechanism) {
		/*
		 * Check if any multi-part sign/verify operation is active.
		 * If a multi-part operation is active, cancel the operation
		 * and remove the operation context.
		 */
		ret = lib_sign_verify_cancel_operation(hsession, op_flag);
		if (ret == CKR_OPERATION_NOT_INITIALIZED)
			ret = CKR_OK;

		return ret;
	}

	/* Validate mechanism operation flag */
	ret = libsess_validate_mechanism(hsession, pmechanism, op_flag);
	if (ret != CKR_OK)
		goto end;

	if (op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN))
		iskey_op[0].type = CKA_SIGN;

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

	ctx->context = NULL;
	/* Set the current state */
	ctx->current_state = OP_INIT;

	/* Set context key handle */
	ctx->hkey = hkey;

	ret = check_signature_mech_params(pmechanism, ctx);
	if (ret != CKR_OK)
		goto end;

	/* Add operation context to list */
	ret = libsess_add_opctx(hsession, op_flag, pmechanism, ctx);

end:
	if (ret != CKR_OK)
		destroy_context(ctx);

	return ret;
}

CK_RV lib_sign_verify_reset(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
			    CK_ULONG ulparameterlen, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	CK_MECHANISM mechanism = { 0 };
	struct lib_signature_ctx *ctx = NULL;

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
		ret = check_signature_params(mechanism.mechanism, pparameter,
					     ulparameterlen, ctx);
		if (ret != CKR_OK)
			return ret;
	}

	ctx->current_state = OP_BEGIN;

	return ret;
}

CK_RV lib_sign_verify_copy_operation(void *src, void **dst)
{
	CK_RV ret = CKR_OK;
	struct lib_signature_ctx *src_ctx = src;
	struct lib_signature_ctx *dst_ctx = NULL;

	dst_ctx = calloc(1, sizeof(struct lib_signature_ctx));
	if (!dst_ctx)
		return CKR_HOST_MEMORY;

	memcpy(dst_ctx, src_ctx, sizeof(*dst_ctx));

	dst_ctx->context = NULL;

	if (dst_ctx->type == SIGN_TYPE_EDDSA) {
		dst_ctx->sign.eddsa.context_data = NULL_PTR;

		if (src_ctx->sign.eddsa.context_data) {
			dst_ctx->sign.eddsa.context_data =
				malloc(dst_ctx->sign.eddsa.context_len);
			if (!dst_ctx->sign.eddsa.context_data) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}

			memcpy(dst_ctx->sign.eddsa.context_data,
			       src_ctx->sign.eddsa.context_data,
			       dst_ctx->sign.eddsa.context_len);
		}
	}

	ret = libdev_copy_operation(src_ctx->context, &dst_ctx->context);
	if (ret != CKR_OK)
		goto end;

	*dst = dst_ctx;

end:
	if (ret != CKR_OK) {
		if (dst_ctx) {
			if (dst_ctx->context)
				free(dst_ctx->context);

			free(dst_ctx);
		}
	}

	return ret;
}

CK_RV lib_sign(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
	       CK_ULONG ulparameterlen, CK_BYTE_PTR pdata, CK_ULONG uldatalen,
	       CK_BYTE_PTR psignature, CK_ULONG_PTR pulsignaturelen,
	       CK_FLAGS op_flag, enum op_state state)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	CK_MECHANISM mechanism = { 0 };
	struct lib_signature_ctx *ctx = NULL;
	struct lib_signature_params params = { 0 };
	CK_BBOOL terminate = CK_TRUE;

	DBG_TRACE("Sign operation");

	if (state != OP_ONE_SHOT && state != OP_NEXT && state != OP_END &&
	    state != OP_FINAL)
		goto end;

	if (state != OP_NEXT && !pulsignaturelen)
		goto end;

	if (state == OP_NEXT || (state == OP_ONE_SHOT && psignature)) {
		if (!uldatalen) {
			ret = CKR_DATA_LEN_RANGE;
			goto end;
		}

		if (!pdata) {
			ret = CKR_DATA_INVALID;
			goto end;
		}
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
	params.pdata = pdata;
	params.uldatalen = uldatalen;
	params.psignature = psignature;
	params.ulsignaturelen = pulsignaturelen ? *pulsignaturelen : 0;
	params.state = state;

	/* Update mechanism parameter */
	if (pparameter) {
		ret = check_signature_params(mechanism.mechanism, pparameter,
					     ulparameterlen, ctx);
		if (ret != CKR_OK)
			goto end;
	}

	/* Run operation */
	ret = libdev_operate_mechanism(hsession, &mechanism, &params);
	if (ret != CKR_BUFFER_TOO_SMALL && ret != CKR_OK)
		goto end;

	/* Update signature length in case of Sign operation */
	if (pulsignaturelen)
		*pulsignaturelen = params.ulsignaturelen;

	if (ret == CKR_OK) {
		ctx->current_state = state;

		if (psignature && (state == OP_ONE_SHOT || state == OP_FINAL))
			ret = libsess_remove_opctx(hsession, op_flag);
	}

	terminate = CK_FALSE;

end:
	if (terminate) {
		/*
		 * Cancel the on-going multipart operation and
		 * remove operation context.
		 */
		(void)lib_sign_verify_cancel_operation(hsession, op_flag);
	}

	return ret;
}

CK_RV lib_verify(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
		 CK_ULONG ulparameterlen, CK_BYTE_PTR pdata, CK_ULONG uldatalen,
		 CK_BYTE_PTR psignature, CK_ULONG ulsignaturelen,
		 CK_FLAGS op_flag, enum op_state state)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	CK_MECHANISM mechanism = { 0 };
	struct lib_signature_ctx *ctx = NULL;
	struct lib_signature_params params = { 0 };
	CK_BBOOL terminate = CK_TRUE;

	DBG_TRACE("Verify operation");

	if (state != OP_ONE_SHOT && state != OP_NEXT && state != OP_END &&
	    state != OP_FINAL)
		goto end;

	if (state != OP_NEXT) {
		if (!psignature) {
			ret = CKR_SIGNATURE_INVALID;
			goto end;
		}

		if (!ulsignaturelen) {
			ret = CKR_SIGNATURE_LEN_RANGE;
			goto end;
		}
	}

	if (state != OP_FINAL && state != OP_END) {
		if (!uldatalen) {
			ret = CKR_DATA_LEN_RANGE;
			goto end;
		}

		if (!pdata) {
			ret = CKR_DATA_INVALID;
			goto end;
		}
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
	params.pdata = pdata;
	params.uldatalen = uldatalen;
	params.psignature = psignature;
	params.ulsignaturelen = ulsignaturelen;
	params.state = state;

	/* Update mechanism parameter */
	if (pparameter) {
		ret = check_signature_params(mechanism.mechanism, pparameter,
					     ulparameterlen, ctx);
		if (ret != CKR_OK)
			goto end;
	}

	/* Run operation */
	ret = libdev_operate_mechanism(hsession, &mechanism, &params);
	if (ret != CKR_OK)
		goto end;

	ctx->current_state = state;

	if (state == OP_ONE_SHOT || state == OP_FINAL)
		ret = libsess_remove_opctx(hsession, op_flag);

	terminate = CK_FALSE;

end:
	if (!terminate)
		return ret;

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

	return ret;
}

CK_RV lib_sign_verify_update(CK_SESSION_HANDLE hsession, CK_BYTE_PTR ppart,
			     CK_ULONG ulpartLen, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	struct lib_signature_ctx *ctx = NULL;
	CK_MECHANISM mechanism = { 0 };
	struct lib_signature_params params = { 0 };
	CK_BBOOL terminate = CK_TRUE;

	DBG_TRACE("Update %s operation",
		  op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN) ? "Sign" : "Verify");

	if (!ppart) {
		ret = CKR_DATA_INVALID;
		goto end;
	}

	if (!ulpartLen) {
		ret = CKR_DATA_LEN_RANGE;
		goto end;
	}

	/* Check that operation is initialized */
	ret = libsess_find_opctx(hsession, op_flag, &mechanism, (void **)&ctx);
	if (ret != CKR_OK)
		goto end;

	ret = libopctx_check_next_state(ctx->current_state, OP_UPDATE,
					&terminate);
	if (ret != CKR_OK)
		goto end;

	params.op_flag = op_flag;
	params.ctx = ctx;
	params.pdata = ppart;
	params.uldatalen = ulpartLen;
	params.state = OP_UPDATE;

	/* Run operation */
	ret = libdev_operate_mechanism(hsession, &mechanism, &params);
	if (ret != CKR_OK)
		goto end;

	ctx->current_state = OP_UPDATE;

	terminate = CK_FALSE;

end:
	if (terminate) {
		/*
		 * Cancel the on-going multipart operation and
		 * remove operation context.
		 */
		(void)lib_sign_verify_cancel_operation(hsession, op_flag);
	}

	return ret;
}
