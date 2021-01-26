/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __TYPES_H__
#define __TYPES_H__

#include "list.h"
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
 * struct libtoken - runtime token information
 * @label: Token label (set thru C_InitToken)
 * @flags: Bits flag of the token's capabilities/status
 * @max_ro_session: Maximum number of red only sessions that can be opened
 *                  with the token at one time by a single application
 * @ro_session_count: Number of read only sessions currently opened with
 *                    the token
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
	CK_ULONG max_ro_session;
	CK_ULONG ro_session_count;
	CK_ULONG max_rw_session;
	CK_ULONG rw_session_count;
	CK_ULONG max_pin_len;
	CK_ULONG min_pin_len;
	CK_ULONG total_pub_mem;
	CK_ULONG free_pub_mem;
	CK_ULONG total_priv_mem;
	CK_ULONG free_priv_mem;
};

#define NO_LOGIN -1UL

struct libobj_obj;

/**
 * struct libobj_list - object lists definition
 */
LLIST_HEAD(libobj_list, libobj_obj);

/**
 * struct libsess - definition of a session element of a session list
 * @slotid: Slot/Token ID
 * @flags: Session flags
 * @callback: Application notification callback (setup C_InitToken)
 * @application: Reference to the application (setup C_InitToken)
 * @objects: Object created by the session
 * @prev: Previous element of the list
 * @next: Next element of the list
 */
struct libsess {
	CK_SLOT_ID slotid;
	CK_FLAGS flags;
	CK_NOTIFY callback;
	CK_VOID_PTR application;
	struct libobj_list objects;
	struct libsess *prev;
	struct libsess *next;
};

/**
 * struct libdevice - definition of a device
 * @slot: Slot information
 * @token: Token information
 * @login_as: Define the type of Cryptoki's user login
 * @mutex_session: Mutex to manage session (create/login/logout/close)
 * @rw_session: List of the Read/Write Sessions
 * @ro_session: List of the Read Only Sessions
 * @objects: List of the token objects (accessible to all devices sessions)
 *
 * A device is the cryptographic module storing keys, making cryptographic
 * operation, ...
 * In our case, a device is a Security Middleware Secure Subsystem.
 * To a device is associated a slot and a token.
 */
struct libdevice {
	struct libslot slot;
	struct libtoken token;
	CK_USER_TYPE login_as;
	CK_VOID_PTR mutex_session;
	LIST_HEAD(rw_sessions, libsess) rw_sessions;
	LIST_HEAD(ro_sessions, libsess) ro_sessions;
	struct libobj_list objects;
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
 * struct libattr_list - Library attribute list
 * @attr: Array of attribute
 * @number: Number of attributes
 */
struct libattr_list {
	CK_ATTRIBUTE_PTR attr;
	size_t number;
};

/**
 * struct libbignumber - Library big number
 * @value: Big number value
 * @length: Length in bytes of the big number
 */
struct libbignumber {
	CK_BYTE_PTR value;
	size_t length;
};

/**
 * struct libbytes - Library bytes array
 * @array: Bytes array
 * @number: Number of bytes
 */
struct libbytes {
	CK_BYTE_PTR array;
	size_t number;
};

/**
 * struct librfc2279 - RFC2279 string data type
 * @string: No NULL terminated string of CK_UTF8CHAR
 * @length: Length of string
 */
struct librfc2279 {
	CK_UTF8CHAR_PTR string;
	size_t length;
};

/**
 * struct libmech_list - Mechanim type list
 * @mech: Pointer to an array of mechanism
 * @number: Number of mechanism
 */
struct libmech_list {
	CK_MECHANISM_TYPE_PTR mech;
	size_t number;
};

#endif /* __TYPES_H__ */
