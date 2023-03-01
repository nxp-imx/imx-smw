set(GROUP PSA)
set(CFG_FILE psa_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})
set(PSA_TEST_CMD ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_psa_test.sh)
set(PSA_CMD ${PSA_TEST_CMD} ${CFG_FILE})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

# Remove ARM PSA test suite
list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_PSA_psa-crypto_001.json)

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")

# Add and install ARM PSA test suite
add_and_install_tests("${TEST_DEF_SRC_DIR}/U_PSA_psa-crypto_001.json" "${CFG_FILES}" "${PSA_CMD}")
