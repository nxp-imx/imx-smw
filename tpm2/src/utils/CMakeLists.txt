file(GLOB utils_src *.c)

target_sources(${PROJECT_NAME} PRIVATE ${utils_src})
