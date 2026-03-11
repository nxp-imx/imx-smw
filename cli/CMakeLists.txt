project(smw-cli VERSION 1.0 LANGUAGES C)

message(STATUS "CLI tools enabled")

add_compile_definitions(
    CLI_VERSION="${PROJECT_VERSION}"
    SMW_LIB_VERSION="${CMAKE_PROJECT_VERSION}"
)

# Generate SMW error table (runs at CMake configure time)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Generate PSA error table at build time (in binary dir)
set(PSA_ERROR_HANDLER_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/psa_error_handler.c)
set(PSA_ERROR_HEADER ${CMAKE_SOURCE_DIR}/public/psa/error.h)
set(PSA_ERROR_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_psa_error_table.py)

add_custom_command(
    OUTPUT ${PSA_ERROR_HANDLER_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${PSA_ERROR_GENERATOR} ${PSA_ERROR_HANDLER_SOURCE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${PSA_ERROR_HEADER} ${PSA_ERROR_GENERATOR}
    COMMENT "Generating PSA error table from psa/error.h"
)

# Generate SMW error table at build time (in binary dir)
set(SMW_ERROR_HANDLER_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/smw_error_handler.c)
set(SMW_STATUS_HEADER ${CMAKE_SOURCE_DIR}/public/smw_status.h)
set(SMW_ERROR_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_smw_error_table.py)

add_custom_command(
    OUTPUT ${SMW_ERROR_HANDLER_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${SMW_ERROR_GENERATOR} ${SMW_ERROR_HANDLER_SOURCE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${SMW_STATUS_HEADER} ${SMW_ERROR_GENERATOR}
    COMMENT "Generating SMW error table from smw_status.h"
)

# Include subdirectories - each sets its own source variables
add_subdirectory(core)
add_subdirectory(psa)
add_subdirectory(smw)

# Include directories for CLI tools

set(CLI_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/inc    # CLI public headers
	${CMAKE_SOURCE_DIR}/inc            # SMW library headers
	${CMAKE_SOURCE_DIR}/public         # SMW public API headers
	${CMAKE_CURRENT_BINARY_DIR}        # For generated files
)

# Executable 1: nxp_smw (SMW API backend)

message(STATUS "Building nxp_smw (SMW API)")

add_executable(nxp_smw
	${CLI_CORE_SOURCES}
	${CLI_SMW_SOURCES}		# SMW-specific implementation
	${SMW_ERROR_HANDLER_SOURCE} 	# Generated file
)

target_include_directories(nxp_smw PRIVATE
	${CLI_INCLUDE_DIRS}
	${CMAKE_CURRENT_SOURCE_DIR}/core
	${CMAKE_CURRENT_SOURCE_DIR}/smw
)

target_link_libraries(nxp_smw PRIVATE smw)

# Executable 2: nxp_psa (PSA API backend)

message(STATUS "Building nxp_psa (PSA API)")

add_executable(nxp_psa
	${CLI_CORE_SOURCES}
	${CLI_PSA_SOURCES}		# PSA-specific implementation
	${PSA_ERROR_HANDLER_SOURCE} 	# Generated file
)

target_include_directories(nxp_psa PRIVATE
	${CLI_INCLUDE_DIRS}
	${CMAKE_CURRENT_SOURCE_DIR}/core
	${CMAKE_CURRENT_SOURCE_DIR}/psa
)

target_link_libraries(nxp_psa PRIVATE smw)

# Installation

install(TARGETS nxp_smw nxp_psa
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		COMPONENT cli-tools)

# Custom targets

add_custom_target(install_cli-tools
		COMMAND "${CMAKE_COMMAND}" --install "${CMAKE_BINARY_DIR}" --component cli-tools
		DEPENDS nxp_smw nxp_psa
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		VERBATIM)

add_custom_target(build_cli-tools DEPENDS nxp_smw nxp_psa)

if(TARGET build_all)
	add_dependencies(build_all build_cli-tools)
endif()

if(TARGET install_all)
	add_dependencies(install_all install_cli-tools)
endif()
