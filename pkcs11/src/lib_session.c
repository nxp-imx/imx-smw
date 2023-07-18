// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include <stdlib.h>

#include "lib_context.h"
#include "lib_device.h"
#include "lib_mutex.h"
#include "lib_object.h"
#include "lib_opctx.h"

#include "trace.h"

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

CK_RV libsess_close(CK_SESSION_HANDLE hsession)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Try to close session %p (slotid = %ld)", sess, sess->slotid);

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

CK_RV libsess_get_slotid(CK_SESSION_HANDLE hsession, CK_SLOT_ID *slotid)
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
