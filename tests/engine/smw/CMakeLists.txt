target_sources(${PROJECT_NAME}
               PRIVATE
               ${CMAKE_CURRENT_SOURCE_DIR}/aead.c
               ${CMAKE_CURRENT_SOURCE_DIR}/cipher.c
               ${CMAKE_CURRENT_SOURCE_DIR}/config.c
               ${CMAKE_CURRENT_SOURCE_DIR}/data.c
               ${CMAKE_CURRENT_SOURCE_DIR}/device.c
               ${CMAKE_CURRENT_SOURCE_DIR}/exec.c
               ${CMAKE_CURRENT_SOURCE_DIR}/hash.c
               ${CMAKE_CURRENT_SOURCE_DIR}/hmac.c
               ${CMAKE_CURRENT_SOURCE_DIR}/info.c
               ${CMAKE_CURRENT_SOURCE_DIR}/key.c
               ${CMAKE_CURRENT_SOURCE_DIR}/keymgr.c
               ${CMAKE_CURRENT_SOURCE_DIR}/keymgr_derive.c
               ${CMAKE_CURRENT_SOURCE_DIR}/mac.c
               ${CMAKE_CURRENT_SOURCE_DIR}/operation_context.c
               ${CMAKE_CURRENT_SOURCE_DIR}/rng.c
               ${CMAKE_CURRENT_SOURCE_DIR}/sign_verify.c
               ${CMAKE_CURRENT_SOURCE_DIR}/storage.c
               ${CMAKE_CURRENT_BINARY_DIR}/status.c)

#
# Execute process with dependency to ensure that the
# status.c is regrenerated each time smw_status.h changes
#
execute_process(COMMAND ${CMAKE_COMMAND}
                        -DENUM=smw_status_code
                        -DINPUT=${CMAKE_SOURCE_DIR}/public/smw_status.h
                        -DSRC=${CMAKE_CURRENT_SOURCE_DIR}/status.c.in
                        -DDST=${CMAKE_CURRENT_BINARY_DIR}/status.c
                        -DOUTPUT_LIST=SMW_STATUS_STR_LIST
                        -P ${CMAKE_SOURCE_DIR}/tests/cmake/enum_to_string.cmake
                DEPENDS ${CMAKE_SOURCE_DIR}/public/smw_status.h)

