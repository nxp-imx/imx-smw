// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "builtin_macros.h"
#include "compiler.h"
#include "s3mu.h"

#include "utils_ex.h"

#define _BIT(x)		((uint32_t)(1U << (x)))
#define MU_READ_HEADER	(0x01u)
#define GET_HDR_SIZE(x) (((x) & (uint32_t)0xFF00) >> 8u)

typedef struct {
	mu_hdr_t header;
	uint32_t payload[S3MU_TR_COUNT - MU_MSG_HEADER_SIZE];
} mu_message_t;

/* Static function to write one word to transmit register specified by index */
static void __no_optimization s3mu_hal_send_data(s3mu_t *mu, uint32_t regid,
						 uint32_t *data)
{
	uint32_t mask = _BIT(regid);

	if (SMW_UTILS_INFINITE_WAIT_FOR(mu->TSR & mask, smw_utils_wait(1)))
		mu->TR[regid] = *data;
}

/* Static function to retrieve one word from receive register specified by index */
static void __no_optimization s3mu_hal_receive_data(s3mu_t *mu, uint32_t regid,
						    uint32_t *data)
{
	uint32_t mask = _BIT(regid);

	if (SMW_UTILS_INFINITE_WAIT_FOR(mu->RSR & mask, smw_utils_wait(1)))
		*data = mu->RR[regid];
}

/* Static function to retrieve one word from receive register specified by index with wait */
static status_t __no_optimization s3mu_hal_receive_data_wait(s3mu_t *mu,
							     uint8_t regid,
							     uint32_t *data,
							     uint32_t wait)
{
	uint32_t mask = _BIT(regid);

	if (!mu || !data)
		return STATUS_S3MU_INVALID_ARGUMENT;

	if (!wait)
		return STATUS_S3MU_REQUEST_TIMEOUT;

	if (!SMW_UTILS_WAIT_FOR(mu->RSR & mask, wait, smw_utils_wait(1)))
		return STATUS_S3MU_REQUEST_TIMEOUT;

	*data = mu->RR[regid];

	return STATUS_SUCCESS;
}

/* Static function to retrieve message form retrieve registers with wait */
static status_t s3mu_read_data_wait(s3mu_t *mu, uint32_t *buf, uint8_t size,
				    uint32_t wait)
{
	uint32_t *p = buf;
	uint8_t msg_size = size;
	uint8_t rx_reg_idx = 0u;
	status_t ret = STATUS_S3MU_INVALID_ARGUMENT;

	if (mu && buf && size) {
		while (msg_size) {
			if (wait) {
				ret = s3mu_hal_receive_data_wait(mu, rx_reg_idx,
								 p, wait);
				if (ret != STATUS_SUCCESS)
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
	status_t ret = STATUS_S3MU_INVALID_ARGUMENT;

	if (mu && buf && size) {
		if (read_header == MU_READ_HEADER) {
			s3mu_hal_receive_data(mu, rx_reg_idx, p);
			msg_size = (GET_HDR_SIZE(*p));
			*size = msg_size;
			rx_reg_idx++;

			if (msg_size > 0)
				msg_size--; /* payload size = size - 1 (header) */
		} else {
			if (SET_OVERFLOW(*size, msg_size))
				goto end;
		}

		while (msg_size != 0u) {
			rx_reg_idx = rx_reg_idx % S3MU_RR_COUNT;
			p++;
			s3mu_hal_receive_data(mu, rx_reg_idx, p);
			rx_reg_idx++;
			msg_size--;
		}

		ret = STATUS_SUCCESS;
	}

end:
	return ret;
}

status_t s3mu_get_response(s3mu_t *mu, void *buf)
{
	size_t size = 0;

	if (!mu || !buf)
		return STATUS_S3MU_INVALID_ARGUMENT;

	return s3mu_read_message(mu, buf, &size, MU_READ_HEADER);
}

status_t s3mu_send_message(s3mu_t *mu, void *buf, uint32_t word_count)
{
	uint32_t *p = buf;
	uint32_t tx_reg_idx = 0u;
	status_t ret = STATUS_S3MU_INVALID_ARGUMENT;

	if (mu && buf && word_count) {
		while (word_count != 0u) {
			s3mu_hal_send_data(mu, tx_reg_idx, p);

			tx_reg_idx++;
			if (tx_reg_idx >= S3MU_TR_COUNT)
				tx_reg_idx = 0;

			p++;
			word_count--;
		}

		ret = STATUS_SUCCESS;
	}

	return ret;
}

status_t s3mu_wait_for_data(s3mu_t *mu, uint32_t *buf, uint32_t word_count,
			    uint32_t wait)
{
	uint8_t size = (word_count & UINT8_MAX);
	status_t ret = STATUS_S3MU_INVALID_ARGUMENT;

	if (mu && buf && wait) {
		if (word_count > S3MU_RR_COUNT)
			ret = STATUS_S3MU_ARGUMENT_OUT_OF_RANGE;
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
