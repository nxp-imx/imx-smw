/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __LIBSMW_TA_H__
#define __LIBSMW_TA_H__

/**
 * libsmw_detach() - Detach from library instance.
 *
 * Return:
 * TEE_SUCCESS        - Operation succeed.
 * TEE_ERROR_GENERIC  - Error during library detach operation.
 */
TEE_Result libsmw_detach(void);

/**
 * libsmw_dispatcher() - Library commands dispatcher.
 * @cmd_id: Command ID.
 * @param_types: TEE parameters.
 * @params: Buffer parameters.
 *
 * Return:
 * TEE_SUCCESS			- Operation succeed.
 * TEE_ERROR_BAD_PARAMETERS	- Command ID is not implemented or parameters
 *                                are bad in specific command.
 * Other error code from specific command.
 */
TEE_Result libsmw_dispatcher(uint32_t cmd_id, uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]);

#endif /* __LIBSMW_TA_H__ */
