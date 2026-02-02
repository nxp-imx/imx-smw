# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

if(CONFIG_SMW_OSAL_ZEPHYR)
    zephyr_library_sources(
        osal.c
        mutex.c
        thread.c
        obj_db.c
        config.c
    )

    zephyr_library_include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/inc
        ${PROJECT_SOURCE_DIR}/public
    )
endif()
