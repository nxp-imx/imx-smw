/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef SMW_STATUS_H
#define SMW_STATUS_H

/* Status codes */
#define SMW_STATUS_OK			    0
#define SMW_STATUS_INVALID_VERSION	    1
#define SMW_STATUS_INVALID_BUFFER	    2
#define SMW_STATUS_EOF			    3
#define SMW_STATUS_SYNTAX_ERROR		    4
#define SMW_STATUS_UNKNOWN_NAME		    5
#define SMW_STATUS_UNKNOWN_ID		    6
#define SMW_STATUS_TOO_LARGE_NUMBER	    7
#define SMW_STATUS_ALLOC_FAILURE	    8
#define SMW_STATUS_INVALID_PARAM	    9
#define SMW_STATUS_VERSION_NOT_SUPPORTED    10
#define SMW_STATUS_SUBSYSTEM_LOAD_FAILURE   11
#define SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE 12
#define SMW_STATUS_SUBSYSTEM_FAILURE	    13
#define SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED 14
#define SMW_STATUS_OPERATION_NOT_SUPPORTED  15
#define SMW_STATUS_OPERATION_NOT_CONFIGURED 16
#define SMW_STATUS_OPERATION_FAILURE	    17

#endif /* SMW_STATUS_H */
