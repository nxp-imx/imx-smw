// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_mac.h"

/**
 * struct mac_data - Data of MAC linked list node.
 * @mac: Buffer containing the MAC generated by SMW.
 * @mac_length: Length of the MAC.
 */
struct mac_data {
	unsigned char *mac;
	unsigned int mac_length;
};

static void mac_free_data(void *data)
{
	struct mac_data *mac_data = data;

	if (mac_data && mac_data->mac)
		free(mac_data->mac);
}

int util_mac_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, &mac_free_data, LIST_ID_TYPE_UINT);
}

int util_mac_add_node(struct llist *list, unsigned int id, unsigned char *mac,
		      unsigned int mac_length)
{
	int res;
	struct mac_data *data;

	if (!list)
		return ERR_CODE(BAD_ARGS);

	data = malloc(sizeof(*data));
	if (!data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	data->mac = mac;
	data->mac_length = mac_length;

	res = util_list_add_node(list, id, data);

	if (res != ERR_CODE(PASSED) && data)
		free(data);

	return res;
}

int util_mac_find_node(struct llist *list, unsigned int id, unsigned char **mac,
		       unsigned int *mac_length)
{
	int res;
	struct mac_data *data = NULL;

	if (!list)
		return ERR_CODE(BAD_ARGS);

	res = util_list_find_node(list, id, (void **)&data);
	if (res == ERR_CODE(PASSED) && !data)
		return ERR_CODE(FAILED);

	if (res == ERR_CODE(PASSED)) {
		if (mac)
			*mac = data->mac;

		if (mac_length)
			*mac_length = data->mac_length;
	}

	return res;
}