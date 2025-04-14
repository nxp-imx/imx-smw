// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <time.h>

#include "compiler.h"
#include "debug.h"
#include "utils.h"

#include "common.h"

struct __packed msg_block {
	uint8_t version;
	uint16_t length;
	uint8_t tag;
	uint32_t flags;
	uint16_t sw_version;
	uint8_t fuse_version;
	uint8_t res_1;
	uint16_t signature_offset;
	uint16_t res_2;
	struct {
		uint8_t flags;
		uint8_t res[3];
		uint8_t iv[32];
	} descriptor;
	struct {
		uint16_t issue_date;
		uint8_t permission;
		uint8_t cert_version;
		uint16_t res_1;
		uint8_t command;
		uint8_t res_2;
		uint8_t uuid[8];
	} header;
};

#define MSG_BLOCK_SIZE sizeof(struct msg_block)

#define MSG_BLOCK_TAG	      0x89
#define MSG_BLOCK_SW_VERSION  0
#define MSG_BLOCK_MONTH_SHIFT 12

void ele_fill_sign_msg_block(void *msg, unsigned char cmd,
			     unsigned int payload_length)
{
	time_t sys_time = 0;
	struct tm *cur_tm = NULL;
	uint16_t month = 0;
	uint16_t year = 0;

	struct msg_block *msg_block = msg;

	SMW_UTILS_MEMSET(msg_block, 0, MSG_BLOCK_SIZE);

	msg_block->tag = MSG_BLOCK_TAG;
	msg_block->sw_version = MSG_BLOCK_SW_VERSION;

	(void)ADD_OVERFLOW(MSG_BLOCK_SIZE, payload_length,
			   &msg_block->signature_offset);

	sys_time = time(NULL);
	if (sys_time) {
		cur_tm = localtime(&sys_time);

		if (cur_tm) {
			month = (cur_tm->tm_mon << MSG_BLOCK_MONTH_SHIFT) &
				UINT16_MAX;
			year = cur_tm->tm_year & UINT16_MAX;
		}
	}

	msg_block->header.issue_date = month | year;

	msg_block->header.command = cmd;
}

unsigned int ele_get_sign_msg_block_length(void)
{
	return MSG_BLOCK_SIZE;
}
