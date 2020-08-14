cmake_minimum_required(VERSION 3.5)

project(test_engine VERSION 1.0 LANGUAGES C)

set(JSON_C_LIB_NAME json-c)
set(JSON_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/json-c-build)
set(JSON_SOURCES_DIR ${CMAKE_CURRENT_BINARY_DIR}/json-c)

macro(find_libjson_c found)
        find_library(JSON_C_LIB ${JSON_C_LIB_NAME} ${JSON_BUILD_DIR})
        if(JSON_C_LIB)
                set(${found} True)
        else()
                set(${found} False)
        endif()
endmacro()

macro(find_json_c_sources found)
        find_path(JSON_C_SOURCES json.h ${CMAKE_CURRENT_BINARY_DIR})
        if(JSON_C_SOURCES)
                set(JSON_SOURCES_DIR ${JSON_C_SOURCES})
                set(${found} True)
        else()
                set(${found} False)
        endif()
endmacro()

find_libjson_c(JSON_LIB_FOUND)
if(NOT ${JSON_LIB_FOUND})
        find_json_c_sources(JSON_SOURCES_FOUND)
        if(NOT ${JSON_SOURCES_FOUND})
                set(JSON_SOURCES_LINK https://github.com/json-c/json-c/archive/master.zip)
                message(STATUS "Downloading json-c library from " ${JSON_SOURCES_LINK})
                execute_process(COMMAND wget ${JSON_SOURCES_LINK}
                                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                                OUTPUT_QUIET
                                RESULT_VARIABLE JSON_DL)

                if(NOT ${JSON_DL} EQUAL 0)
                        message(FATAL_ERROR "\njson-c library download failed\n")
                endif()

                message(STATUS "Unzip json-c library sources in " ${JSON_SOURCES_DIR})
                execute_process(COMMAND unzip master.zip
                                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                                OUTPUT_QUIET
                                RESULT_VARIABLE JSON_UNZIP)
                execute_process(COMMAND mv json-c-master ${JSON_SOURCES_DIR}
                                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                                RESULT_VARIABLE JSON_MV)

                if(NOT ${JSON_UNZIP} EQUAL 0 OR NOT ${JSON_MV} EQUAL 0)
                        message(FATAL_ERROR "\nCan't unzip json-c library\n")
                endif()
        endif()

        set(ENV{CC} ${CMAKE_C_COMPILER})
        set(ENV{AR} ${CMAKE_AR})

        execute_process(COMMAND mkdir ${JSON_BUILD_DIR}
                        RESULT_VARIABLE PRE_BUILD_RES)
        if(NOT ${PRE_BUILD_RES} EQUAL 0)
                message(FATAL_ERROR "\nCan't create ${JSON_BUILD_DIR} directory\n")
        endif()

        set(JSON_CMAKE cmake ${JSON_SOURCES_DIR})
        message(STATUS "Running command: " ${JSON_CMAKE})
        execute_process(COMMAND ${JSON_CMAKE}
                        WORKING_DIRECTORY ${JSON_BUILD_DIR}
                        OUTPUT_QUIET
                        RESULT_VARIABLE JSON_CMAKE_RES)
        if(NOT ${JSON_CMAKE_RES} EQUAL 0)
                message(FATAL_ERROR "\n${JSON_CMAKE} command failed\n")
        endif()

        set(JSON_MAKE make)
        message(STATUS "Building json-c library")
        execute_process(COMMAND ${JSON_MAKE}
                        WORKING_DIRECTORY ${JSON_BUILD_DIR}
                        OUTPUT_QUIET
                        RESULT_VARIABLE JSON_MAKE_RES)
        if(NOT ${JSON_MAKE_RES} EQUAL 0)
                message(FATAL_ERROR "\nCan't build json-c library, make failed\n")
        endif()
endif()

add_executable(${PROJECT_NAME} engine/main.c engine/util.c engine/keymgr.c engine/crypto.c)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/engine/inc)
target_include_directories(${PROJECT_NAME} PRIVATE ${JSON_SOURCES_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/json-c-build)

add_library(libjson-c SHARED IMPORTED)
set(JSON_LIB ${CMAKE_CURRENT_BINARY_DIR}/json-c-build/libjson-c.so)
set_target_properties(libjson-c PROPERTIES IMPORTED_LOCATION ${JSON_LIB})
target_link_libraries(${PROJECT_NAME} PRIVATE libjson-c)

target_link_libraries(${PROJECT_NAME} PRIVATE smw)

set(TEST1_CMD /usr/local/share/smw/tests/scripts/test1.sh)
set(TEST1_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test1.sh)
execute_process(COMMAND chmod u+x ${TEST1_SCRIPT})
add_test(NAME Test1 COMMAND ${TEST1_CMD})

set(TEST2_CMD /usr/local/share/smw/tests/scripts/test2.sh)
set(TEST2_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test2.sh)
execute_process(COMMAND chmod u+x ${TEST2_SCRIPT})
add_test(NAME Test2 COMMAND ${TEST2_CMD})

set(TEST3_CMD /usr/local/share/smw/tests/scripts/test3.sh)
set(TEST3_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test3.sh)
execute_process(COMMAND chmod u+x ${TEST3_SCRIPT})
add_test(NAME Test3 COMMAND ${TEST3_CMD})

set(TEST4_CMD /usr/local/share/smw/tests/scripts/test4.sh)
set(TEST4_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test4.sh)
execute_process(COMMAND chmod u+x ${TEST4_SCRIPT})
add_test(NAME Test4 COMMAND ${TEST4_CMD})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/config DESTINATION share/smw/tests)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/scripts DESTINATION share/smw/tests)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vectors DESTINATION share/smw/tests)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake DESTINATION share/smw/tests)
install(TARGETS ${PROJECT_NAME} DESTINATION bin/smw)
