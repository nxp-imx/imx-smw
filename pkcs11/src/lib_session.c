// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "lib_context.h"
#include "lib_device.h"
#include "lib_mutex.h"
#include "lib_object.h"
#include "lib_opctx.h"
#include "lib_session.h"

#include "lib_cipher.h"
#include "lib_digest.h"
#include "lib_sign_verify.h"

#include "trace.h"
#include "list.h"

static CK_RV get_slotdev(struct libdevice **dev, struct libsess *sess)
{
	CK_RV ret = CKR_OK;

	ret = libdev_get_slotdev(dev, sess->slotid);
	if (ret == CKR_SLOT_ID_INVALID)
		ret = CKR_SESSION_HANDLE_INVALID;

	return ret;
}

struct libsess *find_session(struct libdevice *dev, struct libsess *session)
{
	struct libsess *sess = NULL;

	if (session->flags & CKF_RW_SESSION) {
		LIST_FIND(sess, &dev->rw_sessions, session);
		DBG_TRACE("R/W session %p %sfound", session,
			  session == sess ? "" : "NOT ");
	} else {
		LIST_FIND(sess, &dev->ro_sessions, session);
		DBG_TRACE("R/O session %p %sfound", session,
			  session == sess ? "" : "NOT ");
	}

	return sess;
}

static CK_RV open_rw_session(struct libsess *session, struct libdevice *dev)
{
	if (dev->token.flags & CKF_WRITE_PROTECTED)
		return CKR_TOKEN_WRITE_PROTECTED;

	if (dev->token.max_rw_session != CK_EFFECTIVELY_INFINITE &&
	    dev->token.max_rw_session != CK_UNAVAILABLE_INFORMATION)
		if (dev->token.rw_session_count == dev->token.max_rw_session)
			return CKR_SESSION_COUNT;

	if (ADD_OVERFLOW(dev->token.rw_session_count, 1,
			 &dev->token.rw_session_count))
		return CKR_SESSION_COUNT;

	DBG_TRACE("Open a R/W session %p (%ld/%ld)", session,
		  dev->token.rw_session_count, dev->token.max_rw_session);

	LIST_INSERT_TAIL(&dev->rw_sessions, session);
	return CKR_OK;
}

static CK_RV open_ro_session(struct libsess *session, struct libdevice *dev)
{
	if (dev->login_as == CKU_SO && dev->token.rw_session_count)
		return CKR_SESSION_READ_WRITE_SO_EXISTS;

	if (dev->token.max_ro_session != CK_EFFECTIVELY_INFINITE &&
	    dev->token.max_ro_session != CK_UNAVAILABLE_INFORMATION)
		if (dev->token.ro_session_count == dev->token.max_ro_session)
			return CKR_SESSION_COUNT;

	if (ADD_OVERFLOW(dev->token.ro_session_count, 1,
			 &dev->token.ro_session_count))
		return CKR_SESSION_COUNT;

	DBG_TRACE("Open a RO session %p (%ld/%ld)", session,
		  dev->token.ro_session_count, dev->token.max_ro_session);

	LIST_INSERT_TAIL(&dev->ro_sessions, session);

	return CKR_OK;
}

static CK_RV close_rw_session(struct libdevice *dev, struct libsess *session)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Close R/W session %p", session);

	ret = libobj_list_destroy(&session->objects);
	if (ret != CKR_OK)
		return ret;

	ret = libopctx_list_destroy(&session->opctx);
	if (ret == CKR_OK) {
		LIST_REMOVE(&dev->rw_sessions, session);

		if (DEC_OVERFLOW(dev->token.rw_session_count, 1))
			dev->token.rw_session_count = 0;

		free(session);
	}

	return ret;
}

static CK_RV close_ro_session(struct libdevice *dev, struct libsess *session)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Close RO session %p", session);

	ret = libobj_list_destroy(&session->objects);
	if (ret != CKR_OK)
		return ret;

	ret = libopctx_list_destroy(&session->opctx);
	if (ret == CKR_OK) {
		LIST_REMOVE(&dev->ro_sessions, session);

		if (DEC_OVERFLOW(dev->token.ro_session_count, 1))
			dev->token.ro_session_count = 0;

		free(session);
	}

	return ret;
}

CK_RV libsess_open(CK_SLOT_ID slotid, CK_FLAGS flags, CK_VOID_PTR application,
		   CK_NOTIFY notify, CK_SESSION_HANDLE_PTR hsession)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	const struct libdev *devinfo = NULL;
	struct libsess *sess = NULL;

	DBG_TRACE("Try to open a new session on token #%ld", slotid);

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret != CKR_OK)
		return ret;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	if (!(dev->slot.flags & CKF_TOKEN_PRESENT))
		return CKR_TOKEN_NOT_PRESENT;

	if (!(dev->token.flags & CKF_TOKEN_INITIALIZED))
		return CKR_TOKEN_NOT_RECOGNIZED;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return CKR_HOST_MEMORY;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		goto err;

	if (flags & CKF_RW_SESSION)
		ret = open_rw_session(sess, dev);
	else
		ret = open_ro_session(sess, dev);

	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	if (ret != CKR_OK)
		goto err;

	sess->slotid = slotid;
	sess->flags = flags;
	sess->callback = notify;
	sess->callback_count = 0;
	sess->application = application;

	/* Initialize object list and its mutex */
	ret = LLIST_INIT(&sess->objects);
	if (ret != CKR_OK)
		goto err;

	/* Initialize operations context list and its mutex */
	ret = LLIST_INIT(&sess->opctx);
	if (ret == CKR_OK) {
		*hsession = (CK_SESSION_HANDLE)sess;

		DBG_TRACE("New session %p opened on token #%ld", sess, slotid);
		return ret;
	}

err:
	if (sess)
		free(sess);

	return ret;
}

CK_RV libsess_destroy_query(CK_SESSION_HANDLE hsession)
{
	CK_RV ret = CKR_OK;

	struct libobj_query *query = NULL;
	struct libobj_handles *obj = NULL;
	struct libobj_handles *next = NULL;

	DBG_TRACE("Destroy query list, if any on session %lu", hsession);
	ret = libsess_get_query(hsession, &query);
	if (ret == CKR_OK && query) {
		obj = LIST_FIRST(&query->objects);
		while (obj) {
			next = LIST_NEXT(obj);
			free(obj);
			obj = next;
		}

		free(query);

		ret = libsess_set_query(hsession, NULL);
	}

	return ret;
}

CK_RV libsess_close(CK_SESSION_HANDLE hsession)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Try to close session %p (slotid = %ld)", sess, sess->slotid);

	/* Clean query list, if any */
	ret = libsess_destroy_query(hsession);
	if (ret != CKR_OK)
		return ret;

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	if (find_session(dev, sess) != sess) {
		ret = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	if (sess->flags & CKF_RW_SESSION)
		ret = close_rw_session(dev, sess);
	else
		ret = close_ro_session(dev, sess);

	/* If no more session opened, reset login state */
	if (!dev->token.rw_session_count && !dev->token.ro_session_count)
		dev->login_as = NO_LOGIN;

end:
	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	DBG_TRACE("Closing Session %p return %ld", sess, ret);
	return ret;
}

CK_RV libsess_close_all(CK_SLOT_ID slotid)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libsess *sess = NULL;
	struct libsess *next = NULL;

	DBG_TRACE("Try to close all sessions of token %ld", slotid);

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	DBG_TRACE("RW Session %lu", dev->token.rw_session_count);
	if (dev->token.rw_session_count) {
		sess = LIST_FIRST(&dev->rw_sessions);
		while (sess) {
			next = LIST_NEXT(sess);
			ret = close_rw_session(dev, sess);
			if (ret != CKR_OK)
				goto end;

			sess = next;
		}
	}

	DBG_TRACE("RO Session %lu", dev->token.ro_session_count);
	if (dev->token.ro_session_count) {
		sess = LIST_FIRST(&dev->ro_sessions);
		while (sess) {
			next = LIST_NEXT(sess);
			ret = close_ro_session(dev, sess);
			if (ret != CKR_OK)
				goto end;

			sess = next;
		}
	}

	dev->login_as = NO_LOGIN;

end:
	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	DBG_TRACE("Closing All Sessions return %ld", ret);

	return ret;
}

CK_RV libsess_get_info(CK_SESSION_HANDLE hsession, CK_SESSION_INFO_PTR pinfo)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Try to get session %p information (slotid = %lu)", sess,
		  sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	if (find_session(dev, sess) != sess) {
		ret = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	pinfo->slotID = sess->slotid;
	pinfo->flags = sess->flags;
	pinfo->ulDeviceError = 0;

	switch (dev->login_as) {
	case CKU_USER:
		pinfo->state = (pinfo->flags & CKF_RW_SESSION) ?
				       CKS_RW_USER_FUNCTIONS :
				       CKS_RO_USER_FUNCTIONS;
		break;

	case CKU_SO:
		pinfo->state = (pinfo->flags & CKF_RW_SESSION) ?
				       CKS_RW_SO_FUNCTIONS :
				       CKS_RO_PUBLIC_SESSION;
		break;

	default:
		pinfo->state = (pinfo->flags & CKF_RW_SESSION) ?
				       CKS_RW_PUBLIC_SESSION :
				       CKS_RO_PUBLIC_SESSION;
	}

	ret = CKR_OK;
end:
	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	return ret;
}

CK_RV libsess_login(CK_SESSION_HANDLE hsession, CK_USER_TYPE user)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Try to login as %lu on session %p (slotid = %lu)", user,
		  sess, sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	if (find_session(dev, sess) != sess) {
		ret = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	DBG_TRACE("Session current user = %lu", dev->login_as);
	if (dev->login_as == user) {
		ret = CKR_USER_ALREADY_LOGGED_IN;
		goto end;
	}

	if (dev->login_as != NO_LOGIN) {
		ret = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		goto end;
	}

	if (user == CKU_SO && dev->token.ro_session_count) {
		ret = CKR_SESSION_READ_ONLY_EXISTS;
		goto end;
	}

	DBG_TRACE("Session login is now user = %lu", user);
	dev->login_as = user;

	ret = CKR_OK;
end:
	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	return ret;
}

CK_RV libsess_logout(CK_SESSION_HANDLE hsession)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Logout of session %p (slotid = %lu)", sess, sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	if (find_session(dev, sess) != sess) {
		ret = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	DBG_TRACE("Session current user = %lu", dev->login_as);

	dev->login_as = NO_LOGIN;

	ret = CKR_OK;
end:
	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	return ret;
}

CK_RV libsess_get_user(CK_SESSION_HANDLE hsession, CK_USER_TYPE *user)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	if (!user)
		return ret;

	DBG_TRACE("Get the user logged on session %p", sess);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	DBG_TRACE("Session current user = %lu", dev->login_as);
	*user = dev->login_as;

	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	return ret;
}

CK_RV libsess_validate(CK_SESSION_HANDLE hsession)
{
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	if (!sess)
		return ret;

	DBG_TRACE("Validate session %p (slotid = %lu)", sess, sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	if (find_session(dev, sess) != sess)
		ret = CKR_SESSION_HANDLE_INVALID;

	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	return ret;
}

CK_RV libsess_validate_mechanism(CK_SESSION_HANDLE hsession,
				 CK_MECHANISM_PTR mech, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Validate session %p (slotid = %lu)", sess, sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	if (find_session(dev, sess) != sess)
		ret = CKR_SESSION_HANDLE_INVALID;
	else
		ret = libdev_validate_mechanism(sess->slotid, mech, op_flag);

	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	return ret;
}

CK_RV libsess_get_slotid(CK_SESSION_HANDLE hsession, CK_SLOT_ID_PTR slotid)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Get slot ID of session %p (slotid = %lu)", sess,
		  sess->slotid);

	if (!slotid)
		return ret;

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	*slotid = sess->slotid;

	return ret;
}

CK_RV libsess_get_device(CK_SESSION_HANDLE hsession, struct libdevice **dev)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Get the session %p (slotid = %lu)", sess, sess->slotid);

	if (!dev)
		return ret;

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	ret = get_slotdev(dev, sess);

	return ret;
}

CK_RV libsess_get_objects(CK_SESSION_HANDLE hsession, struct libobj_list **list)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Get slot ID of session %p (slotid = %lu)", sess,
		  sess->slotid);

	if (!list)
		return ret;

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	*list = &sess->objects;

	return ret;
}

CK_RV libsess_set_query(CK_SESSION_HANDLE hsession, struct libobj_query *query)
{
	CK_RV ret = CKR_OK;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Get slot ID of session %p (slotid = %lu)", sess,
		  sess->slotid);

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	sess->query = query;

	return ret;
}

CK_RV libsess_get_query(CK_SESSION_HANDLE hsession, struct libobj_query **query)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Get slot ID of session %p (slotid = %lu)", sess,
		  sess->slotid);

	if (!query)
		return ret;

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	*query = sess->query;

	return ret;
}

CK_RV libsess_callback(CK_SESSION_HANDLE hsession, CK_NOTIFICATION event)
{
	CK_RV ret_callback = CKR_OK;
	CK_RV ret = CKR_OK;
	struct libsess *sess = (struct libsess *)hsession;
	struct libdevice *dev = NULL;

	DBG_TRACE("Call session (%p) callback", sess);

	ret = libsess_get_device(hsession, &dev);
	if (ret != CKR_OK)
		return ret;

	if (!sess->callback)
		return CKR_OK;

	/*
	 * Increment the callback counter
	 */
	ret = libmutex_lock(dev->mutex_session);
	if (ret == CKR_OK) {
		if (ADD_OVERFLOW(sess->callback_count, 1,
				 &sess->callback_count))
			ret = CKR_GENERAL_ERROR;
		libmutex_unlock(dev->mutex_session);
	}

	if (ret != CKR_OK)
		return ret;

	ret_callback = sess->callback(hsession, event, sess->application);

	/*
	 * Decrement the callback counter
	 */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	sess->callback_count--;
	libmutex_unlock(dev->mutex_session);

	if (ret_callback == CKR_CANCEL)
		return CKR_FUNCTION_CANCELED;

	return CKR_OK;
}

CK_RV libsess_add_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag,
			CK_MECHANISM_PTR mech, void *ctx)
{
	CK_RV ret = CKR_OK;
	struct libsess *sess = (struct libsess *)hsession;
	struct libopctx *opctx_find = NULL;
	struct libopctx opctx_add = { 0 };

	DBG_TRACE("Store operation context (sess: %p, op: %lx, mech: %lx)",
		  sess, op_flag, mech->mechanism);

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	ret = LLIST_LOCK(&sess->opctx);
	if (ret != CKR_OK)
		return ret;

	ret = libopctx_find(&sess->opctx, op_flag, &opctx_find);
	if (ret != CKR_OK)
		goto end;

	if (opctx_find) {
		ret = CKR_OPERATION_ACTIVE;
		goto end;
	}

	opctx_add.op_flag = op_flag;
	opctx_add.mech = *mech;
	opctx_add.ctx = ctx;
	ret = libopctx_add(&sess->opctx, &opctx_add);

end:
	LLIST_UNLOCK(&sess->opctx);
	return ret;
}

CK_RV libsess_find_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag,
			 CK_MECHANISM_PTR mech, void **ctx)
{
	CK_RV ret = CKR_OK;
	struct libsess *sess = (struct libsess *)hsession;
	struct libopctx *opctx = NULL;

	DBG_TRACE("Find operation context (sess: %p, op: %lx, mech: %lx)", sess,
		  op_flag, mech->mechanism);

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	ret = LLIST_LOCK(&sess->opctx);
	if (ret != CKR_OK)
		return ret;

	ret = libopctx_find(&sess->opctx, op_flag, &opctx);
	if (ret != CKR_OK)
		goto end;

	if (!opctx) {
		ret = CKR_OPERATION_NOT_INITIALIZED;
		goto end;
	}

	*mech = opctx->mech;
	if (ctx)
		*ctx = opctx->ctx;

end:
	LLIST_UNLOCK(&sess->opctx);
	return ret;
}

CK_RV libsess_remove_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	struct libsess *sess = (struct libsess *)hsession;
	struct libopctx *opctx = NULL;

	DBG_TRACE("Remove operation context (sess: %p, op: %lx)", sess,
		  op_flag);

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	ret = LLIST_LOCK(&sess->opctx);
	if (ret != CKR_OK)
		return ret;

	ret = libopctx_find(&sess->opctx, op_flag, &opctx);
	if (ret != CKR_OK)
		goto end;

	if (opctx)
		ret = libopctx_destroy(&sess->opctx, opctx);

end:
	LLIST_UNLOCK(&sess->opctx);
	return ret;
}

CK_RV libsess_cancel_opctx(CK_SESSION_HANDLE hsession, CK_FLAGS op_flag,
			   void **context)
{
	CK_RV ret;
	struct libsess *sess = (struct libsess *)hsession;
	struct libopctx *opctx = NULL;

	DBG_TRACE("Cancel operation context (sess: %p, op: %lx)", sess,
		  op_flag);

	ret = libsess_validate(hsession);
	if (ret != CKR_OK)
		return ret;

	ret = LLIST_LOCK(&sess->opctx);
	if (ret != CKR_OK)
		return ret;

	ret = libopctx_find(&sess->opctx, op_flag, &opctx);
	if (ret != CKR_OK)
		goto end;

	if (opctx)
		ret = libopctx_cancel(&sess->opctx, opctx, context);

end:
	LLIST_UNLOCK(&sess->opctx);
	return ret;
}

static CK_RV cancel_op(CK_SESSION_HANDLE hSession, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;

	switch (op_flag) {
	case CKF_ENCRYPT:
	case CKF_DECRYPT:
	case CKF_MESSAGE_ENCRYPT:
	case CKF_MESSAGE_DECRYPT:
		ret = lib_cipher_cancel_operation(hSession, op_flag);
		break;

	case CKF_SIGN:
	case CKF_VERIFY:
	case CKF_MESSAGE_SIGN:
	case CKF_MESSAGE_VERIFY:
		ret = lib_sign_verify_cancel_operation(hSession, op_flag);
		break;

	case CKF_DIGEST:
		ret = lib_digest_cancel_operation(hSession);
		break;

	default:
		ret = CKR_GENERAL_ERROR;
		break;
	}

	return ret;
}

static CK_RV calculate_op_state_size(const struct lib_op_state *op_state,
				     CK_ULONG_PTR total_size)
{
	CK_RV ret = CKR_OK;
	CK_ULONG size = 0;
	CK_ULONG ctx_size = 0;
	CK_ULONG handles_size = 0;

	/* Size for operation context count */
	size += sizeof(op_state->op_ctx_count);

	/* Size for operation contexts */
	if (op_state->op_ctx_count > 0) {
		ctx_size = op_state->op_ctx_count * sizeof(struct libopctx);
		if (ADD_OVERFLOW(size, ctx_size, &size)) {
			ret = CKR_STATE_UNSAVEABLE;
			goto end;
		}
	}

	/* Size for object count */
	if (ADD_OVERFLOW(size, sizeof(op_state->obj_count), &size)) {
		ret = CKR_STATE_UNSAVEABLE;
		goto end;
	}

	/* Size for object handles */
	if (op_state->obj_count > 0) {
		handles_size = op_state->obj_count * sizeof(CK_OBJECT_HANDLE);
		if (ADD_OVERFLOW(size, handles_size, &size)) {
			ret = CKR_STATE_UNSAVEABLE;
			goto end;
		}
	}

	*total_size = size;

end:
	return ret;
}

static void free_mech_param(CK_MECHANISM *mech)
{
	if (mech && mech->pParameter) {
		free(mech->pParameter);
		mech->pParameter = NULL;
		mech->ulParameterLen = 0;
	}
}

static CK_RV serialize_op_state(const struct lib_op_state *op_state,
				CK_BYTE_PTR pOperationState)
{
	CK_RV ret = CKR_OK;
	CK_ULONG offset = 0;
	CK_ULONG ctx_size = 0;
	CK_ULONG handles_size = 0;

	/* Serialize operation context count */
	memcpy(pOperationState, &op_state->op_ctx_count,
	       sizeof(op_state->op_ctx_count));
	offset += sizeof(op_state->op_ctx_count);

	/* Serialize operation contexts */
	if (op_state->op_ctx_count > 0 && op_state->op_ctx) {
		ctx_size = op_state->op_ctx_count * sizeof(*op_state->op_ctx);
		memcpy(pOperationState + offset, op_state->op_ctx, ctx_size);
		if (ADD_OVERFLOW(offset, ctx_size, &offset)) {
			ret = CKR_STATE_UNSAVEABLE;
			goto end;
		}
	}

	/* Serialize object count */
	memcpy(pOperationState + offset, &op_state->obj_count,
	       sizeof(op_state->obj_count));
	offset += sizeof(op_state->obj_count);

	/* Serialize object handles */
	if (op_state->obj_count > 0 && op_state->obj_handle) {
		if (MUL_OVERFLOW(op_state->obj_count,
				 sizeof(*op_state->obj_handle),
				 &handles_size)) {
			ret = CKR_STATE_UNSAVEABLE;
			goto end;
		}

		memcpy(pOperationState + offset, op_state->obj_handle,
		       handles_size);
	}

end:
	return ret;
}

static CK_RV deserialize_op_state(CK_BYTE_PTR pOperationState,
				  CK_ULONG ulOperationStateLen,
				  struct lib_op_state *op_state)
{
	CK_RV ret = CKR_OK;
	CK_ULONG offset = 0;
	CK_ULONG size = 0;
	CK_ULONG ctx_size = 0;
	CK_ULONG handles_size = 0;

	memset(op_state, 0, sizeof(*op_state));

	if (ulOperationStateLen < sizeof(op_state->op_ctx_count))
		return CKR_SAVED_STATE_INVALID;

	/* Deserialize operation context count */
	memcpy(&op_state->op_ctx_count, pOperationState + offset,
	       sizeof(op_state->op_ctx_count));
	offset += sizeof(op_state->op_ctx_count);

	/* Deserialize operation contexts */
	if (op_state->op_ctx_count > 0) {
		ctx_size = op_state->op_ctx_count * sizeof(struct libopctx);

		if (ADD_OVERFLOW(offset, ctx_size, &size) ||
		    size > ulOperationStateLen) {
			ret = CKR_SAVED_STATE_INVALID;
			goto end;
		}

		op_state->op_ctx = malloc(ctx_size);
		if (!op_state->op_ctx) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		memcpy(op_state->op_ctx, pOperationState + offset, ctx_size);

		offset += ctx_size;
	}

	if (ADD_OVERFLOW(offset, sizeof(op_state->obj_count), &size) ||
	    size > ulOperationStateLen) {
		ret = CKR_SAVED_STATE_INVALID;
		goto end;
	}

	/* Deserialize object count */
	memcpy(&op_state->obj_count, pOperationState + offset,
	       sizeof(op_state->obj_count));
	offset += sizeof(op_state->obj_count);

	/* Deserialize object handles */
	if (op_state->obj_count > 0) {
		handles_size = op_state->obj_count * sizeof(CK_OBJECT_HANDLE);

		if (ADD_OVERFLOW(offset, handles_size, &size) ||
		    size > ulOperationStateLen) {
			ret = CKR_SAVED_STATE_INVALID;
			goto end;
		}

		op_state->obj_handle = malloc(handles_size);
		if (!op_state->obj_handle) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		memcpy(op_state->obj_handle, pOperationState + offset,
		       handles_size);
	}

end:
	if (ret != CKR_OK) {
		if (op_state->op_ctx) {
			free(op_state->op_ctx);
			op_state->op_ctx = NULL;
		}

		if (op_state->obj_handle) {
			free(op_state->obj_handle);
			op_state->obj_handle = NULL;
		}

		op_state->op_ctx_count = 0;
		op_state->obj_count = 0;
	}

	return ret;
}

static void free_op_state(struct lib_op_state *op_state)
{
	if (!op_state)
		return;

	if (op_state->op_ctx) {
		free(op_state->op_ctx);
		op_state->op_ctx = NULL;
	}

	if (op_state->obj_handle) {
		free(op_state->obj_handle);
		op_state->obj_handle = NULL;
	}

	op_state->op_ctx_count = 0;
	op_state->obj_count = 0;
}

static CK_RV collect_operation_contexts(CK_SESSION_HANDLE hSession,
					CK_BYTE_PTR pOperationState,
					struct lib_op_state *op_state)
{
	CK_RV ret = CKR_OK;
	struct libsess *sess = (struct libsess *)hSession;
	struct libopctx *opctx = NULL;
	struct libopctx *dest_ctx = NULL;
	CK_ULONG ctx_index = 0;
	CK_ULONG ctx_size = 0;
	unsigned int i = 0;

	CK_ULONG op_flags[] = {
		CKF_ENCRYPT,	     CKF_DECRYPT,	 CKF_MESSAGE_ENCRYPT,
		CKF_MESSAGE_DECRYPT, CKF_SIGN,		 CKF_VERIFY,
		CKF_MESSAGE_SIGN,    CKF_MESSAGE_VERIFY, CKF_DIGEST,
	};

	/* Count active multi-part operations */
	op_state->op_ctx_count = 0;
	for (; i < ARRAY_SIZE(op_flags); i++) {
		ret = libopctx_find(&sess->opctx, op_flags[i], &opctx);
		if (ret == CKR_OK && opctx) {
			if (INC_OVERFLOW(op_state->op_ctx_count, 1)) {
				ret = CKR_GENERAL_ERROR;
				goto end;
			}
		}
	}

	op_state->op_ctx = NULL;

	/*
	 * If pOperationState is NULL, only count active operations to calculate
	 * the required buffer size (returned via pulOperationStateLen).
	 */
	if (op_state->op_ctx_count == 0 || !pOperationState) {
		ret = CKR_OK;
		goto end;
	}

	ctx_size = op_state->op_ctx_count * sizeof(struct libopctx);
	op_state->op_ctx = calloc(1, ctx_size);
	if (!op_state->op_ctx) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	/* Copy active operations */
	ctx_index = 0;
	for (i = 0; i < ARRAY_SIZE(op_flags); i++) {
		ret = libopctx_find(&sess->opctx, op_flags[i], &opctx);
		if (ret != CKR_OK || !opctx)
			continue;

		dest_ctx = &op_state->op_ctx[ctx_index];
		ret = libopctx_copy(opctx, dest_ctx);
		if (ret != CKR_OK) {
			ret = CKR_STATE_UNSAVEABLE;
			break;
		}

		ctx_index++;
	}

end:
	if (ret != CKR_OK && op_state->op_ctx)
		free_op_state(op_state);

	return ret;
}

static CK_RV collect_search_objects(CK_SESSION_HANDLE hSession,
				    CK_BYTE_PTR pOperationState,
				    struct lib_op_state *op_state)
{
	CK_RV ret = CKR_OK;
	struct libobj_query *query = NULL;
	struct libobj_handles *obj = NULL;
	CK_ULONG obj_index = 0;
	CK_ULONG handles_size = 0;

	ret = libsess_get_query(hSession, &query);
	if (ret != CKR_OK)
		goto end;

	op_state->obj_count = 0;
	op_state->obj_handle = NULL;

	if (!query) {
		ret = CKR_OK;
		goto end;
	}

	/* Count search objects in query */
	obj = LIST_FIRST(&query->objects);
	while (obj) {
		if (INC_OVERFLOW(op_state->obj_count, 1)) {
			ret = CKR_STATE_UNSAVEABLE;
			goto end;
		}

		obj = LIST_NEXT(obj);
	}

	/*
	 * If pOperationState is NULL, only count the search objects to calculate
	 * the required buffer size (returned via pulOperationStateLen).
	 */
	if (op_state->obj_count == 0 || !pOperationState) {
		ret = CKR_OK;
		goto end;
	}

	handles_size = op_state->obj_count * sizeof(CK_OBJECT_HANDLE);
	op_state->obj_handle = calloc(1, handles_size);
	if (!op_state->obj_handle) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	/* Copy object handles */
	obj = LIST_FIRST(&query->objects);
	obj_index = 0;
	while (obj && obj_index < op_state->obj_count) {
		op_state->obj_handle[obj_index] = obj->handle;
		obj = LIST_NEXT(obj);
		obj_index++;
	}

end:
	if (ret != CKR_OK && op_state->obj_handle)
		free_op_state(op_state);

	return ret;
}

static void release_op_context(struct lib_op_state *op_state)
{
	CK_ULONG ctx_index = 0;
	struct libopctx *opctx = NULL;

	if (!op_state)
		return;

	if (op_state->op_ctx) {
		/* Use libopctx_destroy to properly free each context */
		for (; ctx_index < op_state->op_ctx_count; ctx_index++) {
			opctx = &op_state->op_ctx[ctx_index];

			if (opctx->mech.pParameter)
				free(opctx->mech.pParameter);
		}
	}
}

static CK_RV restore_operation_contexts(CK_SESSION_HANDLE hSession,
					const struct lib_op_state *op_state)
{
	CK_RV ret = CKR_OK;
	struct libopctx active_ctx = { 0 };
	struct libopctx *ctx = NULL_PTR;
	unsigned int i = 0;

	if (op_state->op_ctx_count == 0)
		goto end;

	if (!op_state->op_ctx) {
		ret = CKR_SAVED_STATE_INVALID;
		goto end;
	}

	/* Fetch operation contexts */
	for (; i < op_state->op_ctx_count; i++) {
		ctx = &op_state->op_ctx[i];
		ret = libsess_find_opctx(hSession, ctx->op_flag,
					 &active_ctx.mech, &active_ctx.ctx);
		if (ret != CKR_OK && ret != CKR_OPERATION_NOT_INITIALIZED)
			break;

		/*
		 * If a multi-part operation of the type indicated by @ctx->op_flag
		 * (CK_FLAGS) is currently active in a session, it must be cancelled
		 * before restoring the saved operation state, as required by the
		 * PKCS#11 specification.
		 */
		if (ret == CKR_OK && active_ctx.ctx) {
			ret = cancel_op(hSession, ctx->op_flag);
			if (ret != CKR_OK)
				break;
		}

		ret = libsess_add_opctx(hSession, ctx->op_flag, &ctx->mech,
					ctx->ctx);
		if (ret != CKR_OK)
			break;

		free_mech_param(&active_ctx.mech);
	}

	if (ret != CKR_OK)
		free_mech_param(&active_ctx.mech);

end:
	return ret;
}

static CK_RV restore_search_objects(CK_SESSION_HANDLE hSession,
				    const struct lib_op_state *op_state)
{
	CK_RV status = CKR_OK;
	struct libobj_query *query = NULL_PTR;
	struct libobj_handles *obj = NULL_PTR;
	struct libobj_handles *tmp = NULL_PTR;
	struct libobj_handles *next = NULL_PTR;

	unsigned int i = 0;

	if (op_state->obj_count == 0)
		return status;

	if (!op_state->obj_handle)
		return CKR_SAVED_STATE_INVALID;

	query = calloc(1, sizeof(*query));
	if (!query) {
		status = CKR_HOST_MEMORY;
		goto end;
	}

	/* Create object handles list from saved handles */
	for (; i < op_state->obj_count; i++) {
		obj = calloc(1, sizeof(*obj));
		if (!obj) {
			status = CKR_HOST_MEMORY;
			goto end;
		}

		obj->handle = op_state->obj_handle[i];
		LIST_INSERT_TAIL(&query->objects, obj);
	}

	status = libsess_set_query(hSession, query);

end:
	if (status != CKR_OK) {
		if (query) {
			/* Free any allocated object handles */
			tmp = LIST_FIRST(&query->objects);
			while (tmp) {
				next = LIST_NEXT(tmp);
				free(tmp);
				tmp = next;
			}

			free(query);
		}

		(void)libsess_set_query(hSession, NULL);
	}

	return status;
}

CK_RV libsess_get_operation_state(CK_SESSION_HANDLE hSession,
				  CK_BYTE_PTR pOperationState,
				  CK_ULONG_PTR pulOperationStateLen)
{
	CK_RV ret = CKR_OK;
	struct libsess *sess = (struct libsess *)hSession;
	struct lib_op_state op_state = { 0 };
	CK_ULONG required_size = 0;

	ret = libsess_validate(hSession);
	if (ret != CKR_OK)
		return ret;

	ret = LLIST_LOCK(&sess->opctx);
	if (ret != CKR_OK)
		return ret;

	ret = collect_operation_contexts(hSession, pOperationState, &op_state);
	if (ret != CKR_OK)
		goto end;

	ret = collect_search_objects(hSession, pOperationState, &op_state);
	if (ret != CKR_OK)
		goto end;

	/* Check if there's any state to save */
	if (op_state.op_ctx_count == 0 && op_state.obj_count == 0) {
		ret = CKR_OPERATION_NOT_INITIALIZED;
		goto end;
	}

	/* Calculate required buffer size */
	ret = calculate_op_state_size(&op_state, &required_size);
	if (ret != CKR_OK)
		goto end;

	DBG_TRACE("Total required operation state length = %ld", required_size);

	if (!pOperationState || *pulOperationStateLen < required_size) {
		*pulOperationStateLen = required_size;
		ret = CKR_BUFFER_TOO_SMALL;
		goto end;
	}

	ret = serialize_op_state(&op_state, pOperationState);
	if (ret != CKR_OK)
		goto end;

	*pulOperationStateLen = required_size;

end:
	if (ret != CKR_OK) {
		if (pOperationState && required_size > 0)
			memset(pOperationState, 0, required_size);
	}

	free_op_state(&op_state);

	LLIST_UNLOCK(&sess->opctx);

	return ret;
}

CK_RV libsess_set_operation_state(CK_SESSION_HANDLE hSession,
				  CK_BYTE_PTR pOperationState,
				  CK_ULONG ulOperationStateLen)
{
	CK_RV ret = CKR_OK;

	struct libobj_query *query = NULL;
	struct lib_op_state op_state = { 0 };

	ret = libsess_validate(hSession);
	if (ret != CKR_OK)
		goto end;

	/* Validate and deserialize the operation state */
	ret = deserialize_op_state(pOperationState, ulOperationStateLen,
				   &op_state);
	if (ret != CKR_OK)
		goto end;

	ret = restore_operation_contexts(hSession, &op_state);
	if (ret != CKR_OK)
		goto end;

	ret = libsess_get_query(hSession, &query);
	if (ret != CKR_OK)
		goto end;

	/*
	 * As per PKCS#11 spec, any active object search (C_FindObjectsInit)
	 * must be terminated before restoring a saved operation state.
	 */
	if (query) {
		ret = libsess_destroy_query(hSession);
		if (ret != CKR_OK)
			goto end;
	}

	/* Restore session's object search sate */
	ret = restore_search_objects(hSession, &op_state);

end:
	release_op_context(&op_state);
	free_op_state(&op_state);
	return ret;
}
