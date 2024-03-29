// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <errno.h>
#include <sys/file.h>

#include "local.h"

char *get_strerr(void)
{
	if (__errno_location())
		return strerror(errno);

	return "Unknown error";
}

void dbg_entry(struct obj_entry *entry __maybe_unused)
{
	DBG_PRINTF(DEBUG, "Object ID         : %u\n", entry->id);
	DBG_PRINTF(DEBUG, "       Flags      : %u\n", entry->flags);
	DBG_PRINTF(DEBUG, "       Persistence: %u\n", entry->persistence);
	DBG_PRINTF(DEBUG, "       Size       : %zu\n", entry->info_size);
}

void dbg_entry_info(void *buf, size_t len)
{
	size_t idx = 0;
	char out[256] = { 0 };
	unsigned long off = 0;
	int nb_char = 0;

	if (DBG_LEVEL_DEBUG > DBG_LEVEL)
		return;

	printf("Entry Info: (%p-%zu)\n", buf, len);

	for (idx = 0; idx < len; idx++) {
		if ((!(idx % 16) && idx > 0) || off == (sizeof(out) - 1)) {
			printf("%s\n", out);
			off = 0;
		}

		nb_char = snprintf(out + off, (sizeof(out) - off), "%02X ",
				   ((char *)buf)[idx]);
		if (nb_char < 0)
			break;

		off += nb_char;
	}

	if (off > 0)
		printf("%s\n", out);

	(void)fflush(stdout);
}

void dbg_get_lock_file(int fp)
{
	struct flock lock = { 0 };

	if (fcntl(fp, F_GETLK, &lock) != -1) {
		if (lock.l_type == F_UNLCK)
			DBG_PRINTF(DEBUG, "%s: no lock on this region\n",
				   __func__);
		else
			DBG_PRINTF(DEBUG, "%s: process %d holds the lock\n",
				   __func__, lock.l_pid);
	} else {
		DBG_PRINTF(DEBUG, "%s: %s\n", __func__, get_strerr());
	}
}
