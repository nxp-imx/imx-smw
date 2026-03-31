# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

include(add_target_sources)

add_private_sources(ele_crypto
        ele_common.c
        ele_crypto.c
)

add_private_sources_ifdef(ele_crypto CONFIG_ENABLE_RNG ele_rng.c)

get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_FILE} DIRECTORY)
get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_DIR} DIRECTORY)

add_private_directories(ele_crypto ${CMAKE_PARENT_LIST_DIR} ${INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
