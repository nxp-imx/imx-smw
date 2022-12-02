set(GROUP TEE)
set(CFG_FILE tee_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")
