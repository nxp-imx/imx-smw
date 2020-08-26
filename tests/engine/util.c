// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "smw_keymgr.h"

int copy_file_into_buffer(char *file_name, char **buffer)
{
	int res = 1;
	unsigned int size = 0;
	FILE *f = NULL;

	f = fopen(file_name, "r");
	if (!f) {
		printf("Test engine can't open file %s\n", file_name);
		return res;
	}

	if (fseek(f, 0, SEEK_END)) {
		if (ferror(f))
			perror("fseek() SEEK_END");
		goto exit;
	}

	size = ftell(f);
	if (size == -1) {
		if (ferror(f))
			perror("ftell()");
		goto exit;
	}

	if (fseek(f, 0, SEEK_SET)) {
		if (ferror(f))
			perror("fseek() SEEK_SET");
		goto exit;
	}

	*buffer = malloc(size);
	if (!*buffer) {
		printf("Memory allocation failed\n");
		goto exit;
	}

	if (size != fread(*buffer, sizeof(char), size, f)) {
		if (feof(f))
			printf("Error reading %s: unexpected EOF\n", file_name);
		else if (ferror(f))
			perror("fread()");

		goto exit;
	}

	res = 0;

exit:
	if (fclose(f))
		perror("fclose()");

	if (*buffer && res)
		free(*buffer);

	return res;
}

int key_identifier_add_list(struct key_identifier_list **key_identifiers,
			    struct key_identifier_data *data)
{
	struct key_identifier_node *head = NULL;
	struct key_identifier_node *new = NULL;

	if (!data)
		return 1;

	new = malloc(sizeof(struct key_identifier_node));
	if (!new) {
		printf("ERROR ins %s. Memory allocation failed\n", __func__);
		return 1;
	}

	new->data = data;
	new->next = NULL;

	if (!*key_identifiers) {
		*key_identifiers = malloc(sizeof(struct key_identifier_list));
		if (!*key_identifiers) {
			printf("ERROR ins %s. Memory allocation failed\n",
			       __func__);
			free(new);
			return 1;
		}

		/* New key is the first of the list */
		(*key_identifiers)->head = new;
	} else {
		head = (*key_identifiers)->head;
		while (head->next)
			head = head->next;

		/* New key is the last of the list */
		head->next = new;
	}

	return 0;
}

unsigned long long
find_key_identifier(struct key_identifier_list *key_identifiers,
		    unsigned int id)
{
	struct key_identifier_node *head = NULL;

	if (!key_identifiers)
		return 0;

	head = key_identifiers->head;

	while (head) {
		if (head->data->id == id)
			return head->data->key_identifier;

		head = head->next;
	}

	return 0;
}

void key_identifier_clear_list(struct key_identifier_list *key_identifiers)
{
	struct key_identifier_node *head = NULL;
	struct key_identifier_node *del = NULL;

	if (!key_identifiers)
		return;

	head = key_identifiers->head;

	while (head) {
		del = head;
		head = head->next;
		free(del->data);
		free(del);
	}

	free(key_identifiers);
}

void convert_string_to_hex(char *string, unsigned char *hex,
			   unsigned int hex_len)
{
	char tmp[2] = { 0 };
	char *endptr = NULL;
	int i;
	int j;

	for (i = 0, j = 0; i < strlen(string) && j < hex_len; i += 2, j++) {
		tmp[0] = string[i];
		tmp[1] = string[i + 1];
		hex[j] = strtol(tmp, &endptr, 16);
	}
}
