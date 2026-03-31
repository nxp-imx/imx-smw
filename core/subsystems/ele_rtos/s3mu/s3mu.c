// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "compiler.h"
#include "s3mu.h"

#define _BIT(x)		((uint32_t)(1UL << (x)))
#define MU_READ_HEADER	(0x01u)
#define GET_HDR_SIZE(x) (((x) & (uint32_t)0xFF00) >> 8u)

typedef struct mu_message {
	mu_hdr_t header;
	uint32_t payload[S3MU_TR_COUNT - MU_MSG_HEADER_SIZE];
} mu_message_t;

static void s3mu_hal_send_data(s3mu_t *mu, uint32_t regid, uint32_t *data);
static void s3mu_hal_receive_data(s3mu_t *mu, uint32_t regid, uint32_t *data);
static status_t s3mu_read_data_wait(s3mu_t *mu, uint32_t *buf, uint8_t *size,
				    uint32_t wait);
static status_t s3mu_hal_receive_data_wait(s3mu_t *mu, uint8_t regid,
					   uint32_t *data, uint32_t wait);

/**
 * s3mu_send_message() - Send message to MU
 * @mu: MU peripheral base address
 * @buf: buffer to store read data
 * @wordCount: size of data in words
 *
 * This function writes message into MU registers and send message to EdgeLock Enclave.
 *
 * Return:
 * kStatus_Success - if success
 * kStatus_S3MU_InvalidArgument - if invalid argument
 */
status_t s3mu_send_message(s3mu_t *mu, void *buf, size_t wordCount)
{
	uint8_t tx_reg_idx = 0u;
	uint8_t counter = 0u;
	status_t ret = kStatus_Fail;

	if (!buf) {
		ret = kStatus_S3MU_InvalidArgument;
	} else {
		while (wordCount != 0u) {
			tx_reg_idx = tx_reg_idx % S3MU_TR_COUNT;
			s3mu_hal_send_data(mu, tx_reg_idx,
					   (uint32_t *)buf + counter);
			tx_reg_idx++;
			counter++;
			wordCount--;
		}

		ret = kStatus_Success;
	}

	return ret;
}

/* Static function to write one word to transmit register specified by index */
static void __no_optimization s3mu_hal_send_data(s3mu_t *mu, uint32_t regid,
						 uint32_t *data)
{
	uint32_t mask = (_BIT(regid));

	while ((mu->TSR & mask) == 0u)
		;

	mu->TR[regid] = *data;
}

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
status_t s3mu_get_response(s3mu_t *mu, void *buf)
{
	size_t size;
	(void)size; /* Not used here */

	if (!buf)
		return kStatus_S3MU_InvalidArgument;

	return s3mu_read_message(mu, buf, &size, MU_READ_HEADER);
}

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
			   uint8_t read_header)
{
	uint32_t msg_size = 0u;
	uint32_t rx_reg_idx = 0u;
	uint32_t *buf_ptr = buf;
	status_t ret = kStatus_Fail;

	if (!buf || !size) {
		ret = kStatus_S3MU_InvalidArgument;
	} else {
		if (read_header == MU_READ_HEADER) {
			s3mu_hal_receive_data(mu, rx_reg_idx, buf);
			msg_size = (GET_HDR_SIZE(buf[0]));
			*size = msg_size;
			rx_reg_idx++;
			msg_size--; /* payload size = size - 1 (header) */
		} else {
			msg_size = *size;
		}

		while (msg_size != 0u) {
			rx_reg_idx = rx_reg_idx % S3MU_RR_COUNT;
			buf_ptr++;
			s3mu_hal_receive_data(mu, rx_reg_idx, buf_ptr);
			rx_reg_idx++;
			msg_size--;
		}

		ret = kStatus_Success;
	}

	return ret;
}

/* Static function to retrieve one word from receive register specified by index */
static void __no_optimization s3mu_hal_receive_data(s3mu_t *mu, uint32_t regid,
						    uint32_t *data)
{
	uint32_t mask = _BIT(regid);

	while ((mu->RSR & mask) == 0u)
		;

	*data = mu->RR[regid];
}

/**
 * s3mu_wait_for_data() - Wait and Read data from MU
 * @mu: MU peripheral base address
 * @buf: buffer to store read data
 * @wordCount: size of data in words
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
status_t s3mu_wait_for_data(s3mu_t *mu, uint32_t *buf, size_t wordCount,
			    uint32_t wait)
{
	uint8_t size = (uint8_t)wordCount;
	status_t ret;

	if (!buf)
		ret = kStatus_S3MU_InvalidArgument;
	else if (wordCount > S3MU_RR_COUNT)
		ret = kStatus_S3MU_AgumentOutOfRange;
	else
		ret = s3mu_read_data_wait(mu, buf, &size, wait);

	return ret;
}

/* Static function to retrieve message form retrieve registers with wait */
static status_t s3mu_read_data_wait(s3mu_t *mu, uint32_t *buf, uint8_t *size,
				    uint32_t wait)
{
	uint8_t msg_size = *size;
	uint8_t counter = 0u;
	uint8_t rx_reg_idx = 0u;
	status_t ret = kStatus_Success;

	if (!buf || !size) {
		ret = kStatus_S3MU_InvalidArgument;
	} else {
		while (msg_size) {
			rx_reg_idx = rx_reg_idx % S3MU_RR_COUNT;
			if (wait) {
				ret = s3mu_hal_receive_data_wait(mu, rx_reg_idx,
								 &buf[counter],
								 wait);
				if (ret != kStatus_Success)
					break;
			} else {
				s3mu_hal_receive_data(mu, rx_reg_idx,
						      &buf[counter]);
			}

			rx_reg_idx++;
			counter++;
			msg_size--;
		}
	}

	return ret;
}

/* Static function to retrieve one word from receive register specified by index with wait */
static status_t __no_optimization s3mu_hal_receive_data_wait(s3mu_t *mu,
							     uint8_t regid,
							     uint32_t *data,
							     uint32_t wait)
{
	uint32_t mask = _BIT(regid);

	while ((mu->RSR & mask) == 0u) {
		if (--wait == 0u)
			return kStatus_S3MU_RequestTimeout;
	}

	*data = mu->RR[regid];

	return kStatus_Success;
}

/**
 * s3mu_init() - Init MU
 * @mu: MU peripheral base address
 * @size: Size of the MU peripheral address space
 *
 * This function does nothing. MU is initialized after leaving ROM.
 *
 * Return:
 * None
 */
__weak void s3mu_init(s3mu_t *mu, size_t size)
{
	/* nothing to do for initialization */
}

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
uint32_t s3mu_compute_msg_crc(uint32_t *msg, uint32_t msg_len)
{
	uint32_t crc;
	uint32_t i;

	crc = 0u;
	for (i = 0u; i < msg_len; i++)
		crc ^= *(msg + i);

	return crc;
}
