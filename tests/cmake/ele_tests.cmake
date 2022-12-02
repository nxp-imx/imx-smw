set(GROUP ELE)
set(CFG_FILE ele_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

# Remove failing test due to ELE Library or FW issues
list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/F_${GROUP}_Thread_001.json)

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")
