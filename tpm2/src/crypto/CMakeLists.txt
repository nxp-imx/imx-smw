file(GLOB crypto_src *.c)

target_sources(${PROJECT_NAME} PRIVATE ${crypto_src})
