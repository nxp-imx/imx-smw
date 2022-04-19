set(SUBSYSTEMS ELE)
set(CFG_FILE ele_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})
set(CMD_SUSPEND ${TEST_KEYMGR_SUSPEND_RESUME_CMD} ${CFG_FILE})

# Get all test definition files except those in multiple parts
FILE(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${SUBSYSTEMS}_*_???.json)

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}" "${SUBSYSTEMS}")

# Create suspend resume test definition files list and install test
FILE(GLOB TESTS ${TEST_DEF_SRC_DIR}/F_${SUBSYSTEMS}_Keymgr_001.?.json)

add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD_SUSPEND}" "${SUBSYSTEMS}")
