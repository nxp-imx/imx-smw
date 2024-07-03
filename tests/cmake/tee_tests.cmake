set(GROUP TEE)
set(CMD ${TEST_CMD})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

add_and_install_tests("${TESTS}" "${CMD}")
