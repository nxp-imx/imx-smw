set(GROUP "ELETEE")
set(CMD ${TEST_CMD} ${CFG_FILE})

# Get all test definition files except those in multiple parts
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*_???.json)

add_and_install_tests("${TESTS}" "${CMD}")
