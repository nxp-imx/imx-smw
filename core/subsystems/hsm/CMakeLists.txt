set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:hsm> PARENT_SCOPE)

find_file(ZLIB_LIB_FILE libz.so ${ZLIB_LIB_PATH})

set(HSM_LIB_FILE_NAME "hsm_lib.a")
set(SECO_NVM_MANAGER_LIB_FILE_NAME "seco_nvm_manager.a")

macro(find_seco_libs export_dir found)
    find_file(SECO_NVM_MANAGER_LIB_FILE ${SECO_NVM_MANAGER_LIB_FILE_NAME}
              ${export_dir}/usr/lib)
    find_path(SECO_NVM_MANAGER_INCLUDE_PATH seco_nvm.h
              ${export_dir}/usr/include)
    find_file(HSM_LIB_FILE ${HSM_LIB_FILE_NAME} ${export_dir}/usr/lib)
    find_path(HSM_LIB_INCLUDE_PATH hsm_api.h ${export_dir}/usr/include/hsm)

    if(SECO_NVM_MANAGER_LIB_FILE AND
       SECO_NVM_MANAGER_INCLUDE_PATH AND
       HSM_LIB_FILE AND
       HSM_LIB_INCLUDE_PATH)
        set(${found} True)
    else()
        set(${found} False)
    endif()
endmacro()

find_seco_libs(${SECO_LIBS_EXPORT_DIR} SECO_LIBS_FOUND)

if(NOT SECO_LIBS_FOUND)
    find_file(SECO_MAKEFILE Makefile ${SECO_LIBS_EXPORT_DIR}/..)

    if(SECO_MAKEFILE)
        set(ENV{CC} ${CMAKE_C_COMPILER})
        set(ENV{AR} ${CMAKE_AR})

        if(ZLIB_INCLUDE_PATH)
            set(ENV{CPATH} $ENV{CPATH}:${ZLIB_INCLUDE_PATH})
        endif()

        get_filename_component(SECO_SOURCES ${SECO_MAKEFILE} DIRECTORY)

        message(STATUS "Building seco libs")
        set(SECO_MAKE make)
        set(SECO_MAKE_ARGS clean ${HSM_LIB_FILE_NAME} ${SECO_NVM_MANAGER_LIB_FILE_NAME})
        execute_process(
            COMMAND ${SECO_MAKE} ${SECO_MAKE_ARGS}
            WORKING_DIRECTORY ${SECO_SOURCES}
            RESULT_VARIABLE seco_build_res
        )

        if(NOT ${seco_build_res} EQUAL 0)
            message(FATAL_ERROR "\nFailed to build seco libs from"
                                "\n${SECO_LIBS_EXPORT_DIR}/.. .\n")
        endif()

        file(GLOB
             SECO_EXPORTED_LIBS
             LIST_DIRECTORIES False
             "${SECO_SOURCES}/*.a")

        file(COPY
             ${SECO_EXPORTED_LIBS}
             DESTINATION ${SECO_LIBS_EXPORT_DIR}/usr/lib)

        file(COPY
             "${SECO_SOURCES}/include"
             DESTINATION ${SECO_LIBS_EXPORT_DIR}/usr)

        find_seco_libs(${SECO_LIBS_EXPORT_DIR} SECO_LIBS_FOUND)

        if(NOT SECO_LIBS_FOUND)
            message(FATAL_ERROR "\nSeco libs export directory not valid.\n")
        endif()
    endif()
endif()

set(INCLUDE_DIR ${INCLUDE_DIR} ${SECO_NVM_MANAGER_INCLUDE_PATH}
    ${HSM_LIB_INCLUDE_PATH})

add_library(hsm OBJECT "" ${INCLUDE_DIR})
target_sources(hsm PRIVATE
               hsm.c load.c common.h
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c>)
target_include_directories(hsm PRIVATE ${INCLUDE_DIR})

