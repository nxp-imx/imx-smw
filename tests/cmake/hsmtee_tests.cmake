set(GROUP "HSMTEE")
set(CFG_FILE api_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})

# Get all test definition files except those in multiple parts
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*_???.json)

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")
