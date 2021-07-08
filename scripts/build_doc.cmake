list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
find_package(Sphinx REQUIRED)
find_package(Kerneldoc REQUIRED)

string(REPLACE " " ";" BUILD_DOC_BUILDER "${BUILD_DOC_BUILDER}")

foreach(BUILDER ${BUILD_DOC_BUILDER})
    message(STATUS "BUILDER: ${BUILDER}")
    execute_process(COMMAND
                    ${SPHINX_EXECUTABLE} -M ${BUILDER}
                    ${BUILD_DOC_SOURCE_DIR} ${BUILD_DOC_OUTPUT_DIR})
endforeach()