file(GLOB tss2_src *.c)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	list(FILTER tss2_src EXCLUDE REGEX "trace.c$")
endif()

target_sources(${PROJECT_NAME} PRIVATE ${tss2_src})

target_include_directories(${PROJECT_NAME} PRIVATE
	./include
        ${TSS2_INCLUDE_DIRS}
	${CMAKE_SOURCE_DIR}/inc)

add_subdirectory(utils)
add_subdirectory(commands)
add_subdirectory(crypto)
add_subdirectory(session)
