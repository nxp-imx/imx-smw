/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

/**
 * tls_mac_finish() - Compute TLS 1.2 finished message
 * @hdl: Pointer to the HSM handles structure.
 * @args: Pointer to SMW signature arguments.
 *
 * Return:
 * SMW_STATUS_OK			- Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation not supported
 * SMW_STATUS_OUTPUT_TOO_SHORT		- Output buffer length is too short
 * SMW_STATUS_INVALID_PARAM		- One of the parameters is invalid
 * SMW_STATUS_SUBSYSTEM_FAILURE		- Subsystem failure
 */
int tls_mac_finish(struct hdl *hdl, void *args);
