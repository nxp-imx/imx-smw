/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __KEYMGR_H__
#define __KEYMGR_H__

/**
 * generate_key() - Generate a key.
 * @args: Generate key args.
 * @key_identifiers: Key identifier linked list where smw key identifier
 *                   pointer will be saved.
 *
 * Return:
 * 0	- Success.
 * 1	- Fail.
 */
int generate_key(json_object *args,
		 struct key_identifier_list **key_identifiers);

/**
 * delete_key() - Delete a key.
 * @args: Delete key args.
 * @key_identifiers: Key identifier linked list where smw key identifier
 *                   pointer is saved.
 *
 * Return:
 * 0	- Success.
 * 1	- Fail.
 */
int delete_key(json_object *args, struct key_identifier_list *key_identifiers);

#endif /* __KEYMGR_H__ */
