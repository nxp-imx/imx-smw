set(GROUP API)
set(CFG_FILE api_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})

# Install config files
file(GLOB CFG_FILES ${SMW_CONFIG_SRC_DIR}/config_*.txt)
list(APPEND CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})

file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}*.json)

add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")
