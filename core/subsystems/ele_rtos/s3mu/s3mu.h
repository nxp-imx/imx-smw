/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __S3MU_DRIVER_H__
#define __S3MU_DRIVER_H__

#include <stdint.h>
#include <stddef.h>

#include "status.h"

#define MU_MSG_HEADER_SIZE (1U)

#define MESSAGING_TAG_COMMAND (0x17u)
#define MESSAGING_TAG_REPLY   (0xE1u)

/**
 * kStatus_S3MU_AgumentOutOfRange - S3MU status for out of range access.
 * kStatus_S3MU_InvalidArgument - S3MU status for invalid argument check.
 * kStatus_S3MU_RequestTimeout - S3MU status for timeout.
 * kStatus_S3MU_Busy - S3MU status for reservation by other core.
 */
enum {
	kStatus_S3MU_AgumentOutOfRange = MAKE_STATUS_ELEMU(0x1u),
	kStatus_S3MU_InvalidArgument = MAKE_STATUS_ELEMU(0x2u),
	kStatus_S3MU_RequestTimeout = MAKE_STATUS_ELEMU(0x3u),
	kStatus_S3MU_Busy = MAKE_STATUS_ELEMU(0x4u),
};

typedef struct {
	union {
		uint32_t value;
		struct {
			uint8_t ver;
			uint8_t size;
			uint8_t command;
			uint8_t tag;
		} hdr_byte;
	};
} mu_hdr_t;

/** S3MU - Size of Registers Arrays */
#define S3MU_TR_COUNT 8u
#define S3MU_RR_COUNT 4u

/**
 * s3mu_t - Register Layout Typedef
 * @VER: Version ID Register, offset: 0x0
 * @PAR: Parameter Register, offset: 0x4
 * @UNUSED0: Unused Register 0, offset: 0x8
 * @SR: Status Register, offset: 0xC
 * @TCR: Transmit Control Register, offset: 0x120
 * @TSR: Transmit Status Register, offset: 0x124
 * @RCR: Receive Control Register, offset: 0x128
 * @RSR: Receive Status Register, offset: 0x12C
 * @UNUSED1: Unused Register 1, offset: 0x1FC
 * @TR: Transmit Register, array offset: 0x200, array step: 0x4
 * @RR: Receive Register, array offset: 0x280, array step: 0x4
 * Note: Unused registers are reserved for future use and should not be accessed.
 */
typedef struct {
	uint32_t VER;
	uint32_t PAR;
	uint32_t UNUSED0;
	uint32_t SR;
	uint8_t RESERVED_0[272];
	uint32_t TCR;
	uint32_t TSR;
	uint32_t RCR;
	uint32_t RSR;
	uint8_t RESERVED_1[204];
	uint32_t UNUSED1;
	uint32_t TR[S3MU_TR_COUNT];
	uint8_t RESERVED_2[96];
	uint32_t RR[S3MU_RR_COUNT];
} s3mu_t;

/**
 * s3mu_send_message() - Send message to MU
 * @mu: MU peripheral base address
 * @buf: buffer to store read data
 * @word_count: size of data in words
 *
 * This function writes message into MU registers and send message to EdgeLock Enclave.
 *
 * Return:
 * kStatus_Success - if success
 * kStatus_S3MU_InvalidArgument - if invalid argument
 */
status_t s3mu_send_message(s3mu_t *mu, void *buf, uint32_t word_count);

/**
 * s3mu_get_response() - Get response from MU
 * @mu: MU peripheral base address
 * @buf: buffer to store read data
 *
 * This function reads response data from EdgeLock Enclave if available.
 *
 * Return:
 * kStatus_Success - if success
 * kStatus_S3MU_InvalidArgument - if invalid argument
 */
status_t s3mu_get_response(s3mu_t *mu, void *buf);

/**
 * s3mu_wait_for_data() - Wait and Read data from MU
 * @mu: MU peripheral base address
 * @buf: buffer to store read data
 * @word_count: size of data in words
 * @wait: number of iterations to wait
 *
 * This function waits limited time (ticks) and tests if data are ready to be read.
 * When data are ready, reads them into buffer.
 *
 * Return:
 * kStatus_Success - if success
 * kStatus_S3MU_RequestTimeout - if timeout
 * kStatus_S3MU_InvalidArgument - if invalid argument
 * kStatus_S3MU_AgumentOutOfRange - if argument out of range
 */
status_t s3mu_wait_for_data(s3mu_t *mu, uint32_t *buf, uint32_t word_count,
			    uint32_t wait);

/**
 * s3mu_read_message() - Read message from MU
 * @mu: MU peripheral base address
 * @buf: buffer to store read data
 * @size: If read_header equals MU_READ_HEADER,
 *        size represent number of word obtained from header.
 *        If read header not equals MU_READ_HEADER,
 *        size is used to determine number of word to be read.
 * @read_header: specifies if size is obtained by response header or provided in parameter
 *
 * This function reads message data from EdgeLock Enclave if available.
 *
 * Return:
 * kStatus_Success - if success
 * kStatus_S3MU_InvalidArgument - if invalid argument
 */
status_t s3mu_read_message(s3mu_t *mu, uint32_t *buf, size_t *size,
			   uint8_t read_header);

/**
 * s3mu_init() - Init MU
 * @mu: MU peripheral base address
 * @size: Size of the MU peripheral address space
 *
 * This function needs to be called at least once before using the MU communication functions.
 *
 * Return:
 * None
 */
void s3mu_init(s3mu_t *mu, size_t size);

/**
 * s3mu_compute_msg_crc() - Computes CRC
 * @msg: pointer to message
 * @msg_len: size of message in words
 *
 * This function computes CRC of input message.
 *
 * Return:
 * CRC32 checksum value
 */
uint32_t s3mu_compute_msg_crc(uint32_t *msg, uint32_t msg_len);

#endif /* __S3MU_DRIVER_H__ */
