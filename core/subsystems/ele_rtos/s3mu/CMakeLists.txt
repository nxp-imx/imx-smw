# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

include(add_target_sources)

add_private_sources(s3mu s3mu.c)

get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_FILE} DIRECTORY)
get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_DIR} DIRECTORY)

add_private_directories(s3mu ${CMAKE_PARENT_LIST_DIR} ${INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
