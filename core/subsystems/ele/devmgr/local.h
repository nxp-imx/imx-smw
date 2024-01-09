/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __LOCAL_H__
#define __LOCAL_H__

#include "common.h"

/**
 * ele_devmgr_fill_msg_block() - Fill the signed message block
 * @msg: Message block to be filled
 * @cmd: Payload command
 * @payload_length: Length of the signed message payload
 *
 * Fill the signed message block fields that are not fixed.
 */
void ele_devmgr_fill_msg_block(void *msg, unsigned char cmd,
			       unsigned int payload_length);

/**
 * ele_devmgr_get_msg_block_length() - Return the signed message block length
 *
 * Return:
 * Length of signed message block
 */
unsigned int ele_devmgr_get_msg_block_length(void);

#endif /* __LOCAL_H__ */
