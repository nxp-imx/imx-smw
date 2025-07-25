set(GROUP PSA)
set(CMD ${TEST_CMD})
set(PSA_TEST_CMD ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_psa_test.sh)
set(PSA_CMD ${PSA_TEST_CMD})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

# Remove ARM PSA test suite
list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_PSA_psa-crypto_001.json)

if(NOT ENABLE_TLS)
    list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_001.json)
    list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_002.json)
    list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_003.json)
    list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_004.json)
    list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_005.json)
endif()

add_and_install_tests("${TESTS}" "${CMD}")

# Add and install ARM PSA test suite
add_and_install_tests("${TEST_DEF_SRC_DIR}/U_PSA_psa-crypto_001.json" "${PSA_CMD}")
