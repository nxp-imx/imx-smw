cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})

project(psatest VERSION 1.0 LANGUAGES C)

enable_testing()

set(PSA_CUSTOM_TEST_LIST "custom_test_list.txt")
set(PSA_ARCH_TESTS_SUITE CRYPTO)
string(TOLOWER ${PSA_ARCH_TESTS_SUITE} PSA_ARCH_TESTS_API_DIR)

add_subdirectory(psa-arch-tests)

configure_file(${TEST_SCRIPTS_SRC}/run_psa_test.sh.in
               ${TEST_SCRIPTS_BIN}/run_psa_test.sh
               @ONLY)

add_executable(${PROJECT_NAME}
               EXCLUDE_FROM_ALL
               main.c)

add_dependencies(${PROJECT_NAME} ${PSA_ARCH_TESTS})

target_link_libraries(${PROJECT_NAME} PRIVATE ${JSONC_LIBRARY})
target_link_libraries(${PROJECT_NAME} PRIVATE pthread)
target_link_libraries(${PROJECT_NAME} PRIVATE smw)
target_link_libraries(${PROJECT_NAME} PRIVATE ${PSA_LIBS})

if(TEE_TESTS_ENABLED)
    add_subdirectory(tee)
endif()

# Add PSA testsuite
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${PSA_ARCH_TESTS}/${PSA_ARCH_TESTS_API_DIR}/${PSA_CUSTOM_TEST_LIST}
        DESTINATION ${SMW_TESTS_TARGET_PSA_DIR}/${PSA_ARCH_TESTS}/${PSA_ARCH_TESTS_API_DIR}
        EXCLUDE_FROM_ALL
        COMPONENT ${PROJECT_NAME})

install(FILES ${TEST_SCRIPTS_BIN}/run_psa_test.sh
        DESTINATION ${SMW_TESTS_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_EXECUTE OWNER_READ
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL OPTIONAL)

add_custom_target(install_${PROJECT_NAME}
        COMMAND "${CMAKE_COMMAND}" -DCOMPONENT=${PROJECT_NAME}
                -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_install.cmake"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        VERBATIM)

if(TARGET install_tests)
    add_dependencies(install_tests install_${PROJECT_NAME})
endif()

if(TARGET build_tests)
    add_dependencies(build_tests ${PROJECT_NAME})
endif()


