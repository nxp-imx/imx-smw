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

/* Static function to write one word to transmit register specified by index */
static void __no_optimization s3mu_hal_send_data(s3mu_t *mu, uint32_t regid,
						 uint32_t *data)
{
	uint32_t mask = (_BIT(regid));

	while ((mu->TSR & mask) == 0u)
		;

	mu->TR[regid] = *data;
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

/* Static function to retrieve one word from receive register specified by index with wait */
static status_t __no_optimization s3mu_hal_receive_data_wait(s3mu_t *mu,
							     uint8_t regid,
							     uint32_t *data,
							     uint32_t wait)
{
	uint32_t mask = _BIT(regid);

	if (!wait)
		return kStatus_S3MU_RequestTimeout;

	while ((mu->RSR & mask) == 0u) {
		if (--wait == 0u)
			return kStatus_S3MU_RequestTimeout;
	}

	*data = mu->RR[regid];

	return kStatus_Success;
}

/* Static function to retrieve message form retrieve registers with wait */
static status_t s3mu_read_data_wait(s3mu_t *mu, uint32_t *buf, uint8_t size,
				    uint32_t wait)
{
	uint32_t *p = buf;
	uint8_t msg_size = size;
	uint8_t rx_reg_idx = 0u;
	status_t ret = kStatus_S3MU_InvalidArgument;

	if (buf && size) {
		while (msg_size) {
			if (wait) {
				ret = s3mu_hal_receive_data_wait(mu, rx_reg_idx,
								 p, wait);
				if (ret != kStatus_Success)
					break;
			} else {
				s3mu_hal_receive_data(mu, rx_reg_idx, p);
			}

			rx_reg_idx = (rx_reg_idx + 1) % S3MU_RR_COUNT;
			p++;
			msg_size--;
		}
	}

	return ret;
}

status_t s3mu_read_message(s3mu_t *mu, uint32_t *buf, size_t *size,
			   uint8_t read_header)
{
	uint32_t msg_size = 0u;
	uint32_t rx_reg_idx = 0u;
	uint32_t *p = buf;
	status_t ret = kStatus_S3MU_InvalidArgument;

	if (buf && size) {
		if (read_header == MU_READ_HEADER) {
			s3mu_hal_receive_data(mu, rx_reg_idx, p);
			msg_size = (GET_HDR_SIZE(*p));
			*size = msg_size;
			rx_reg_idx++;

			if (msg_size > 0)
				msg_size--; /* payload size = size - 1 (header) */
		} else {
			msg_size = *size;
		}

		while (msg_size != 0u) {
			rx_reg_idx = rx_reg_idx % S3MU_RR_COUNT;
			p++;
			s3mu_hal_receive_data(mu, rx_reg_idx, p);
			rx_reg_idx++;
			msg_size--;
		}

		ret = kStatus_Success;
	}

	return ret;
}

status_t s3mu_get_response(s3mu_t *mu, void *buf)
{
	size_t size;
	(void)size; /* Not used here */

	if (!buf)
		return kStatus_S3MU_InvalidArgument;

	return s3mu_read_message(mu, buf, &size, MU_READ_HEADER);
}

status_t s3mu_send_message(s3mu_t *mu, void *buf, uint32_t word_count)
{
	uint32_t *p = buf;
	uint32_t tx_reg_idx = 0u;
	status_t ret = kStatus_S3MU_InvalidArgument;

	if (buf && word_count) {
		while (word_count != 0u) {
			s3mu_hal_send_data(mu, tx_reg_idx, p);

			tx_reg_idx++;
			if (tx_reg_idx >= S3MU_TR_COUNT)
				tx_reg_idx = 0;

			p++;
			word_count--;
		}

		ret = kStatus_Success;
	}

	return ret;
}

status_t s3mu_wait_for_data(s3mu_t *mu, uint32_t *buf, uint32_t word_count,
			    uint32_t wait)
{
	uint8_t size = (word_count & UINT8_MAX);
	status_t ret = kStatus_S3MU_InvalidArgument;

	if (buf && wait) {
		if (word_count > S3MU_RR_COUNT)
			ret = kStatus_S3MU_AgumentOutOfRange;
		else
			ret = s3mu_read_data_wait(mu, buf, size, wait);
	}

	return ret;
}

__weak void s3mu_init(s3mu_t *mu, size_t size)
{
	/* nothing to do for initialization */
}

uint32_t s3mu_compute_msg_crc(uint32_t *msg, uint32_t msg_len)
{
	uint32_t crc;
	uint32_t i;

	crc = 0u;
	for (i = 0u; i < msg_len; i++)
		crc ^= *(msg + i);

	return crc;
}
