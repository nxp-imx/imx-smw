target_sources(${PROJECT_NAME}
               PRIVATE
               ${CMAKE_CURRENT_SOURCE_DIR}/cipher.c
               ${CMAKE_CURRENT_SOURCE_DIR}/exec.c
               ${CMAKE_CURRENT_SOURCE_DIR}/hash.c
               ${CMAKE_CURRENT_SOURCE_DIR}/key.c
               ${CMAKE_CURRENT_SOURCE_DIR}/keymgr.c
               ${CMAKE_CURRENT_SOURCE_DIR}/mac.c
               ${CMAKE_CURRENT_SOURCE_DIR}/rng.c
               ${CMAKE_CURRENT_SOURCE_DIR}/sign_verify.c
               ${CMAKE_CURRENT_BINARY_DIR}/status.c)

#
# Execute process with dependency to ensure that the
# status.c is regrenerated each time psa/error.h changes
#
execute_process(COMMAND ${CMAKE_COMMAND}
                        -DPREFIX=PSA
                        -DINPUT=${CMAKE_SOURCE_DIR}/public/psa/error.h
                        -DSRC=${CMAKE_CURRENT_SOURCE_DIR}/status.c.in
                        -DDST=${CMAKE_CURRENT_BINARY_DIR}/status.c
                        -DOUTPUT_LIST=PSA_STATUS_STR_LIST
                        -P ${CMAKE_SOURCE_DIR}/tests/cmake/const_to_string.cmake
                DEPENDS ${CMAKE_SOURCE_DIR}/public/psa/error.h
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

