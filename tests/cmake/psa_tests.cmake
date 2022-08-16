set(GROUP PSA)
set(CFG_FILE psa_config.txt)
set(PSA_TEST_CMD ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_psa_test.sh)
set(CMD ${PSA_TEST_CMD} ${CFG_FILE})

# Get all PSA test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")
