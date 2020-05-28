/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __TYPES_H__
#define __TYPES_H__

#include "pkcs11smw.h"

/**
 * struct libdev - constant information about a device
 * @name: Name of the device
 * @description: Description of the device
 * @manufacturer: ID of the device's manufacturer
 * @model: Device's model
 * @serial: Device's serial number
 * @version: Device's version
 * @flags_slot: Bits flag of the slot's harcoded capabilities
 * @flags_token: Bits flag of the token's hardcoded capabilities
 */
struct libdev {
	const char *name;
	const char *description;
	const char *manufacturer;
	const char *model;
	const char *serial;
	CK_VERSION version;
	CK_FLAGS flags_slot;
	CK_FLAGS flags_token;
};

/**
 * struct libslot - runtime slot information
 * @flags: Bits flag of the slot's capabilities/status
 */
struct libslot {
	CK_FLAGS flags;
};

/**
 * struct libslot - runtime token information
 * @label: Token label (set thru C_InitToken)
 * @flags: Bits flag of the token's capabilities/status
 * @max_session: Maximum number of sessions that can be opened
 *               with the token at one time by a single application
 * @session_count: Number of sessions currently opened with the token
 * @max_rw_session: Maximum number of read/write sessions that can be opened
 *                  with the token at one time by a single application
 * @rw_session_count: Number of read/write sessions currently opened with
 *                    the token
 * @max_pin_len: maximum length in bytes of the PIN
 * @min_pin_len: minimum length in bytes of the PIN
 * @total_pub_mem: Total amount of memory on the token in bytes in which
 *                 public objects may be stored
 * @free_pub_mem: Amount of free (unused) memory on the token in bytes
 *                for public objects
 * @total_priv_mem: Total amount of memory on the token in bytes in which
 *                  private objects may be stored
 * @free_priv_mem: Amount of free (unused) memory on the token in bytes
 *                 for private objects
 */
struct libtoken {
	CK_UTF8CHAR label[32];
	CK_FLAGS flags;
	CK_ULONG max_session;
	CK_ULONG session_count;
	CK_ULONG max_rw_session;
	CK_ULONG rw_session_count;
	CK_ULONG max_pin_len;
	CK_ULONG min_pin_len;
	CK_ULONG total_pub_mem;
	CK_ULONG free_pub_mem;
	CK_ULONG total_priv_mem;
	CK_ULONG free_priv_mem;
};

/**
 * struct libdevice - definition of a device
 * @slot: Slot information
 * @token: Token information
 *
 * A device is the cryptographic module storing keys, making cryptographic
 * operation, ...
 * In our case, a device is a Security Middleware Secure Subsystem.
 * To a device is associated a slot and a token.
 */
struct libdevice {
	struct libslot slot;
	struct libtoken token;
};

/**
 * struct libmutex - Mutex functions
 * @create: Create a mutex
 * @destroy: Destroy a mutex
 * @lock: Lock a mutex
 * @unlock: Unlock a mutex
 */
struct libmutex {
	CK_CREATEMUTEX create;
	CK_DESTROYMUTEX destroy;
	CK_LOCKMUTEX lock;
	CK_UNLOCKMUTEX unlock;
};

/**
 * struct libcaps - Library capabilities
 * @flags: Capabilities flags
 * @use_os_thread: Library can create its own thread with OS primitive
 * @use_os_mutex: OS Mutex Primitive can be used
 * @multi_thread: Multi-threading is enabled
 */
struct libcaps {
	unsigned int flags;
	bool use_os_thread;
	bool use_os_mutex;
	bool multi_thread;
};

/**
 * struct libctx - Library context
 * @initialized: Library is initialized
 * @caps: Library capabilities
 * @mutex: Mutex operations
 * @devices: Devices info/status
 */
struct libctx {
	bool initialized;
	struct libcaps caps;
	struct libmutex mutex;
	struct libdevice *devices;
};

#endif /* __TYPES_H__ */
