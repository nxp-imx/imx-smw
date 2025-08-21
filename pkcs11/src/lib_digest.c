// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>

#include "lib_digest.h"
#include "lib_device.h"
#include "lib_session.h"
#include "lib_object.h"

#include "trace.h"

static CK_RV lib_digest_cancel_operation(CK_SESSION_HANDLE hsession)
{
	CK_RV ret = CKR_OK;

	struct lib_digest_ctx *ctx = NULL;

	CK_MECHANISM mechanism = { 0 };

	ret = libsess_find_opctx(hsession, CKF_DIGEST, &mechanism,
				 (void **)&ctx);
	if (ret != CKR_OK)
		return ret;

	if (!ctx) {
		ret = libsess_remove_opctx(hsession, CKF_DIGEST);
		return ret;
	}

	switch (ctx->current_state) {
	case OP_INIT:
	case OP_ONE_SHOT:
		ret = libsess_remove_opctx(hsession, CKF_DIGEST);
		break;

	case OP_UPDATE:
	case OP_FINAL:
		if (ctx->context)
			ret = libsess_cancel_opctx(hsession, CKF_DIGEST,
						   (void **)&ctx->context);
		else
			ret = libsess_remove_opctx(hsession, CKF_DIGEST);

		break;

	default:
		break;
	}

	if (ctx)
		free(ctx);

	return ret;
}

CK_RV lib_digest_init(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR pmechanism)
{
	CK_RV ret = CKR_OK;

	struct lib_digest_ctx *ctx = NULL;

	if (!pmechanism) {
		/*
		 * Check if any multi-part digest operation is active.
		 * If a multi-part operation is active, cancel the operation
		 * and remove the operation context.
		 */
		ret = lib_digest_cancel_operation(hsession);
		if (ret == CKR_OPERATION_NOT_INITIALIZED)
			ret = CKR_OK;

		goto end;
	}

	ret = libsess_validate_mechanism(hsession, pmechanism, CKF_DIGEST);
	if (ret != CKR_OK)
		goto end;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	/* Set the current state */
	ctx->current_state = OP_INIT;

	ret = libsess_add_opctx(hsession, CKF_DIGEST, pmechanism, ctx);

end:
	if (ret != CKR_OK && ctx)
		free(ctx);

	return ret;
}

CK_RV lib_digest(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pdata,
		 CK_ULONG data_len, CK_BYTE_PTR pdigest,
		 CK_ULONG_PTR pdigest_len, enum op_state state)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;

	struct lib_digest_ctx *ctx = NULL;
	CK_MECHANISM mechanism = { 0 };
	struct libdig_params params = { 0 };
	CK_BBOOL terminate = CK_TRUE;

	DBG_TRACE("Perform digest operation");

	if (state != OP_ONE_SHOT && state != OP_UPDATE && state != OP_FINAL)
		goto end;

	if (state == OP_ONE_SHOT || state == OP_UPDATE) {
		if (!pdata || !data_len)
			goto end;
	}

	if ((state == OP_ONE_SHOT || state == OP_FINAL) && !pdigest_len)
		goto end;

	ret = libsess_find_opctx(hsession, CKF_DIGEST, &mechanism,
				 (void **)&ctx);
	if (ret != CKR_OK)
		goto end;

	ret = libopctx_check_next_state(ctx->current_state, state, &terminate);
	if (ret != CKR_OK)
		goto end;

	params.ctx = ctx;
	params.pdata = pdata;
	params.data_len = data_len;
	params.pdigest = pdigest;
	params.digest_len = pdigest_len ? *pdigest_len : 0;
	params.state = state;

	ret = libdev_operate_mechanism(hsession, &mechanism, &params);
	if (ret != CKR_BUFFER_TOO_SMALL && ret != CKR_OK)
		goto end;

	/* Update digest buffer length */
	if (pdigest_len)
		*pdigest_len = params.digest_len;

	if (ret == CKR_OK) {
		ctx->current_state = state;

		if (pdigest && (state == OP_ONE_SHOT || state == OP_FINAL))
			goto end;
	}

	terminate = CK_FALSE;

end:
	if (terminate) {
		/*
		 * Cancel the on-going multipart operation and
		 * remove operation context.
		 */
		(void)lib_digest_cancel_operation(hsession);
	}

	return ret;
}

CK_RV lib_digest_key(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE hkey)
{
	CK_RV ret = CKR_OK;

	CK_ULONG key_len = 0;
	CK_OBJECT_CLASS class = 0;
	CK_BYTE_PTR key_value = NULL_PTR;
	CK_ATTRIBUTE key_class = { CKA_CLASS, &class, sizeof(class) };
	CK_ATTRIBUTE key_length = { CKA_VALUE_LEN, &key_len, sizeof(key_len) };
	CK_ATTRIBUTE key_value_attr = { CKA_VALUE, NULL_PTR, 0 };

	/* Get key's class */
	ret = libobj_get_attribute(hsession, hkey, &key_class, 1);
	if (ret != CKR_OK)
		goto end;

	if (class != CKO_SECRET_KEY) {
		ret = CKR_KEY_INDIGESTIBLE;
		goto end;
	}

	/* Get key length */
	ret = libobj_get_attribute(hsession, hkey, &key_length, 1);
	if (ret != CKR_OK) {
		ret = CKR_KEY_INDIGESTIBLE;
		goto end;
	}

	key_value = calloc(1, key_len * sizeof(*key_value));
	if (!key_value) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	key_value_attr.pValue = key_value;
	key_value_attr.ulValueLen = key_len;

	/* Get the key value */
	ret = libobj_get_attribute(hsession, hkey, &key_value_attr, 1);
	if (ret != CKR_OK || !key_value_attr.ulValueLen) {
		ret = CKR_KEY_INDIGESTIBLE;
		goto end;
	}

	ret = lib_digest(hsession, key_value, key_len, NULL_PTR, NULL_PTR,
			 OP_UPDATE);

end:
	if (key_value)
		free(key_value);

	return ret;
}

CK_RV lib_digest_copy_operation(void *src, void **dst)
{
	CK_RV ret = CKR_HOST_MEMORY;

	struct lib_digest_ctx *src_ctx = src;
	struct lib_digest_ctx *dst_ctx = NULL;

	dst_ctx = calloc(1, sizeof(struct lib_digest_ctx));
	if (!dst_ctx)
		goto end;

	dst_ctx->current_state = src_ctx->current_state;

	ret = libdev_copy_operation(src_ctx->context, &dst_ctx->context);
	if (ret != CKR_OK)
		goto end;

	*dst = dst_ctx;

end:
	if (ret != CKR_OK && dst_ctx) {
		if (dst_ctx->context)
			free(dst_ctx->context);

		free(dst_ctx);
	}

	return ret;
}
