file(GLOB commands_src *.c)

target_sources(${PROJECT_NAME} PRIVATE ${commands_src})
