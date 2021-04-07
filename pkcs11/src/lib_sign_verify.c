// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
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
		return true;

	default:
		return false;
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
 * @pmechanism: Pointer to mechanism
 * @ctx: Pointer to signature context
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - Mechanism parameters invalid
 * CKR_OK                             - Success
 */
static CK_RV check_rsa_pss(CK_MECHANISM_PTR pmechanism,
			   struct lib_signature_ctx *ctx)
{
	CK_RV ret;
	CK_MECHANISM_TYPE mech_hash;
	CK_MECHANISM_TYPE mgf_hash = 0;
	CK_RSA_PKCS_PSS_PARAMS_PTR mech_params;

	DBG_TRACE("Check RSA PSS signature mechanism parameter");

	if (pmechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
		return CKR_MECHANISM_PARAM_INVALID;

	/* Get hash mechanism from mechanism type */
	mech_hash = get_hash_mech_from_rsa_pss_mech(pmechanism->mechanism);

	mech_params = (CK_RSA_PKCS_PSS_PARAMS_PTR)pmechanism->pParameter;

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

	if (mech_params->sLen)
		ctx->salt_len = mech_params->sLen;

	return CKR_OK;
}

/**
 * check_mech_params() - Check Sign Verify mechanism parameters
 * @pmechanism: Pointer to mechanism
 * @ctx: Pointer to signature context
 *
 * This functions checks that @pmechanism parameters are consistent with
 * @pmechanism type.
 *
 * Return:
 * CKR_MECHANISM_PARAM_INVALID        - @pmechanism parameters are invalid
 * CKR_OK                             - Success
 */
static CK_RV check_mech_params(CK_MECHANISM_PTR pmechanism,
			       struct lib_signature_ctx *ctx)
{
	DBG_TRACE("Check Sign Verify mechanism parameter");

	if (!pmechanism->pParameter)
		return CKR_OK;

	if (is_rsa_pss_mechanism(pmechanism->mechanism))
		return check_rsa_pss(pmechanism, ctx);

	/* Parameters are set but ignored */
	return CKR_OK;
}

CK_RV lib_sign_verify_init(CK_SESSION_HANDLE hsession,
			   CK_MECHANISM_PTR pmechanism, CK_OBJECT_HANDLE hkey,
			   CK_FLAGS op_flag)
{
	CK_RV ret;
	struct lib_signature_ctx *ctx;
	CK_BBOOL key_op = false;
	CK_ATTRIBUTE iskey_op[] = {
		{ CKA_VERIFY, &key_op, sizeof(key_op) },
	};

	DBG_TRACE("Initialize %s operation",
		  op_flag == CKF_SIGN ? "Sign" : "Verify");

	if (pmechanism) {
		/* Validate mechanism operation flag */
		ret = libsess_validate_mechanism(hsession, pmechanism, op_flag);
		if (ret != CKR_OK)
			return ret;
	} else {
		/* Remove operation context */
		return libsess_remove_opctx(hsession, op_flag);
	}

	if (op_flag == CKF_SIGN)
		iskey_op[0].type = CKA_SIGN;

	ret = libobj_get_attribute(hsession, hkey, iskey_op,
				   ARRAY_SIZE(iskey_op));

	if (ret == CKR_ATTRIBUTE_TYPE_INVALID)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	if (ret != CKR_OK)
		return ret;

	if (!key_op)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return CKR_HOST_MEMORY;

	ctx->hash_mech = 0;
	ctx->salt_len = 0;

	/* Check mechanism parameters */
	ret = check_mech_params(pmechanism, ctx);
	if (ret != CKR_OK)
		goto end;

	/* Set context key handle */
	ctx->hkey = hkey;

	/* Add operation context to list */
	ret = libsess_add_opctx(hsession, op_flag, pmechanism, ctx);

end:
	if (ret != CKR_OK)
		free(ctx);

	return ret;
}

CK_RV lib_sign(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pdata,
	       CK_ULONG uldatalen, CK_BYTE_PTR psignature,
	       CK_ULONG_PTR pulsignaturelen)
{
	CK_RV ret;
	CK_MECHANISM mechanism = { 0 };
	struct lib_signature_ctx *ctx;
	struct lib_signature_params params = { 0 };

	DBG_TRACE("Sign operation");

	if (!pulsignaturelen) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (psignature && !pdata) {
		ret = CKR_DATA_INVALID;
		goto end;
	}

	if (psignature && !uldatalen) {
		ret = CKR_DATA_LEN_RANGE;
		goto end;
	}

	/* Check that operation is initialized */
	ret = libsess_find_opctx(hsession, CKF_SIGN, &mechanism, (void **)&ctx);
	if (ret != CKR_OK)
		goto end;

	params.op_flag = CKF_SIGN;
	params.ctx = ctx;
	params.pdata = pdata;
	params.uldatalen = uldatalen;
	params.psignature = psignature;
	params.ulsignaturelen = *pulsignaturelen;

	/* Run operation */
	ret = libdev_operate_mechanism(hsession, &mechanism, &params);

	if (ret == CKR_BUFFER_TOO_SMALL || ret == CKR_OK) {
		/* Update signature length in case of Sign operation */
		*pulsignaturelen = params.ulsignaturelen;

		/*
		 * Return CKR_BUFFER_TOO_SMALL doesn't terminate the
		 * active signing operation
		 * Return CKR_OK when goal is to determine the length of
		 * the buffer needed to hold the signature doesn't
		 * terminate the active signing operation
		 */
		if (ret == CKR_BUFFER_TOO_SMALL || !psignature)
			return ret;
	}

end:
	/* Remove operation context */
	if (ret != CKR_OK)
		(void)libsess_remove_opctx(hsession, CKF_SIGN);
	else
		ret = libsess_remove_opctx(hsession, CKF_SIGN);

	return ret;
}

CK_RV lib_verify(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pdata,
		 CK_ULONG uldatalen, CK_BYTE_PTR psignature,
		 CK_ULONG ulsignaturelen)
{
	CK_RV ret;
	CK_MECHANISM mechanism = { 0 };
	struct lib_signature_ctx *ctx;
	struct lib_signature_params params = { 0 };

	DBG_TRACE("Verify operation");

	if (!pdata) {
		ret = CKR_DATA_INVALID;
		goto end;
	}

	if (!uldatalen) {
		ret = CKR_DATA_LEN_RANGE;
		goto end;
	}

	if (!psignature) {
		ret = CKR_SIGNATURE_INVALID;
		goto end;
	}

	if (!ulsignaturelen) {
		ret = CKR_SIGNATURE_LEN_RANGE;
		goto end;
	}

	/* Check that operation is initialized */
	ret = libsess_find_opctx(hsession, CKF_VERIFY, &mechanism,
				 (void **)&ctx);
	if (ret != CKR_OK)
		goto end;

	params.op_flag = CKF_VERIFY;
	params.ctx = ctx;
	params.pdata = pdata;
	params.uldatalen = uldatalen;
	params.psignature = psignature;
	params.ulsignaturelen = ulsignaturelen;

	/* Run operation */
	ret = libdev_operate_mechanism(hsession, &mechanism, &params);

end:
	/* Remove operation context */
	if (ret != CKR_OK)
		(void)libsess_remove_opctx(hsession, CKF_VERIFY);
	else
		ret = libsess_remove_opctx(hsession, CKF_VERIFY);

	return ret;
}
