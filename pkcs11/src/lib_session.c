// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdlib.h>

#include "lib_context.h"
#include "lib_device.h"
#include "lib_mutex.h"

#include "trace.h"

/**
 * struct libsess - definition of a session element of a session list
 * @slotid: Slot/Token ID
 * @flags: Session flags
 * @callback: Application notification callback (setup C_InitToken)
 * @application: Reference to the application (setup C_InitToken)
 * @prev: Previous element of the list
 * @next: Next element of the list
 */
struct libsess {
	CK_SLOT_ID slotid;
	CK_FLAGS flags;
	CK_NOTIFY callback;
	CK_VOID_PTR application;
	struct libsess *prev;
	struct libsess *next;
};

static CK_RV get_slotdev(struct libdevice **dev, struct libsess *sess)
{
	CK_RV ret;

	ret = libdev_get_slotdev(dev, sess->slotid);
	if (ret == CKR_SLOT_ID_INVALID)
		ret = CKR_SESSION_HANDLE_INVALID;

	return ret;
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

static CK_RV close_rw_session(bool find, struct libdevice *dev,
			      struct libsess *session)
{
	struct libsess *sess;

	DBG_TRACE("Try to close R/W session %p", session);

	if (find) {
		LIST_FIND(sess, &dev->rw_sessions, session);
		if (!sess)
			return CKR_SESSION_HANDLE_INVALID;

		DBG_TRACE("R/W session %p found", session);
	}

	LIST_REMOVE(&dev->rw_sessions, session);
	dev->token.rw_session_count--;

	free(session);

	return CKR_OK;
}

static CK_RV close_ro_session(bool find, struct libdevice *dev,
			      struct libsess *session)
{
	struct libsess *sess;

	DBG_TRACE("Try to close RO session %p", session);

	if (find) {
		LIST_FIND(sess, &dev->ro_sessions, session);
		if (!sess)
			return CKR_SESSION_HANDLE_INVALID;

		DBG_TRACE("RO session %p found", session);
	}

	LIST_REMOVE(&dev->ro_sessions, session);
	dev->token.ro_session_count--;

	free(session);

	return CKR_OK;
}

CK_RV libsess_open(CK_SLOT_ID slotid, CK_FLAGS flags, CK_VOID_PTR application,
		   CK_NOTIFY notify, CK_SESSION_HANDLE_PTR hsession)
{
	CK_RV ret;
	struct libdevice *dev;
	const struct libdev *devinfo;
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

	sess = malloc(sizeof(*sess));
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
	sess->application = application;

	*hsession = (CK_SESSION_HANDLE)sess;

	DBG_TRACE("New session %p opened on token #%ld", sess, slotid);

	return CKR_OK;

err:
	if (sess)
		free(sess);

	return ret;
}

CK_RV libsess_close(CK_SESSION_HANDLE hsession)
{
	CK_RV ret;
	struct libdevice *dev;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Try to close session %p (slotid = %ld)", sess, sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	if (sess->flags & CKF_RW_SESSION)
		ret = close_rw_session(true, dev, sess);
	else
		ret = close_ro_session(true, dev, sess);

	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	DBG_TRACE("Closing Session %p return %ld", sess, ret);
	return ret;
}

CK_RV libsess_close_all(CK_SLOT_ID slotid)
{
	CK_RV ret;
	struct libdevice *dev;
	struct libsess *sess;
	struct libsess *next;

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
			ret = close_rw_session(false, dev, sess);
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
			ret = close_ro_session(false, dev, sess);
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
	CK_RV ret;
	struct libdevice *dev;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Try to get session %p information (slotid = %lu)", sess,
		  sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

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

	return CKR_OK;
}

CK_RV libsess_login(CK_SESSION_HANDLE hsession, CK_USER_TYPE user)
{
	CK_RV ret;
	struct libdevice *dev;
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
	CK_RV ret;
	struct libdevice *dev;
	struct libsess *sess = (struct libsess *)hsession;

	DBG_TRACE("Logout of session %p (slotid = %lu)", sess, sess->slotid);

	ret = get_slotdev(&dev, sess);
	if (ret != CKR_OK)
		return ret;

	/* Lock session mutex */
	ret = libmutex_lock(dev->mutex_session);
	if (ret != CKR_OK)
		return ret;

	DBG_TRACE("Session current user = %lu", dev->login_as);

	dev->login_as = NO_LOGIN;

	/* Unlock session mutex */
	libmutex_unlock(dev->mutex_session);

	return CKR_OK;
}
