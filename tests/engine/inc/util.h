/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

/**
 * struct key_identifier_data
 * @id: Local ID of the key identifier. Comes from test vectors.
 * @key_identifier: Key identifier assigned by SMW.
 */
struct key_identifier_data {
	unsigned int id;
	unsigned long long key_identifier;
};

/**
 * struct key_identifier_node
 * @data: Data of the node.
 * @next: Pointer to next node
 */
struct key_identifier_node {
	struct key_identifier_data *data;
	struct key_identifier_node *next;
};

/**
 * struct key_identifier_list - Linked list to save keys identifiers pointers.
 * @head: Pointer to the head of the linked list
 */
struct key_identifier_list {
	struct key_identifier_node *head;
};

/**
 * copy_file_into_buffer() - Copy file content into buffer.
 * @file_name: Name of the file to copy.
 * @buffer: Pointer to buffer to fill. Allocate by this function and must be
 *          free by caller.
 *
 * Return:
 * 0	- Success.
 * 1	- Fail.
 */
int copy_file_into_buffer(char *file_name, char **buffer);

/**
 * key_identifier_add_list() - Add a new node in a key identifier linked list.
 * @key_identifiers: Pointer to linked list.
 * @data: Data to add.
 *
 * Return:
 * 0	- Success.
 * 1	- Fail.
 */
int key_identifier_add_list(struct key_identifier_list **key_identifiers,
			    struct key_identifier_data *data);

/**
 * find_key_identifier() - Search a key identifier.
 * @key_identifiers: Key identifier linked list where the research is done.
 * @id: Id of the key identifier.
 *
 * Return:
 * Key identifier	- Success.
 * NULL				- Fail.
 */
unsigned long long
find_key_identifier(struct key_identifier_list *key_identifiers,
		    unsigned int id);

/**
 * key_identifier_clear_list() - Clear key identifier linked list.
 * @key_identifiers: Key identifier linked list to clear.
 *
 * This function also free smw key identifier pointer presents in node data.
 *
 * Return:
 * none
 */
void key_identifier_clear_list(struct key_identifier_list *key_identifiers);

/**
 * convert_string_to_hex() - Convert ASCII string to hex string.
 * @string: Input string.
 * @hex: Hex output string. Should be allocated by caller.
 * @hex_len: @hex len in bytes.
 *
 * This function convert an ASCII string that represents hexadecimal values
 * to hex string.
 *
 * Return:
 * none.
 */
void convert_string_to_hex(char *string, unsigned char *hex,
			   unsigned int hex_len);

#endif /* __UTIL_H__ */
