project(smw_pkcs11 VERSION 1.0 LANGUAGES C)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
	add_compile_options(-Wall -Wextra -Werror)
endif()

add_library(${PROJECT_NAME} SHARED "")

add_subdirectory(src)

# Include pkcs11 headers
#
target_include_directories(${PROJECT_NAME} PUBLIC import)

set_target_properties(${PROJECT_NAME} PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR})

set_target_properties(${PROJECT_NAME} PROPERTIES
	C_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN ON)

string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,--no-undefined")
