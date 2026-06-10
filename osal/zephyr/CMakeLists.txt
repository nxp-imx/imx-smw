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

        if(CONFIG_MMU)
                zephyr_compile_definitions(CACHE_MODE_WRITE_THROUGH=1)
                zephyr_library_sources(shared_mem.c)
                zephyr_library_sources(get_mu_base.c)
        endif()

        zephyr_library_include_directories(
                ${CMAKE_CURRENT_SOURCE_DIR}
                ${PROJECT_SOURCE_DIR}/inc
                ${PROJECT_SOURCE_DIR}/public
        )

        if(CONFIG_SMW_NVM_MANAGER)
                zephyr_library_sources(file.c)

                zephyr_library_link_libraries(FS)
        endif()
endif()
