project(smw-cli VERSION 1.0 LANGUAGES C)

message(STATUS "CLI tools enabled")

add_compile_definitions(
    CLI_VERSION="${PROJECT_VERSION}"
    SMW_LIB_VERSION="${CMAKE_PROJECT_VERSION}"
)

# Generate SMW error table (runs at CMake configure time)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Generate backend.h for each executable (no USE_*_BACKEND in source code)

set(BACKEND_H_IN ${CMAKE_CURRENT_SOURCE_DIR}/inc/backend.h.in)

# SMW backend header
set(SMW_BACKEND_H_DIR ${CMAKE_CURRENT_BINARY_DIR}/smw_backend)
set(CLI_BACKEND_NAME  "SMW API")
set(CLI_BACKEND_NOTE  "")
set(CLI_HAS_BACKEND_NOTE 0)
configure_file(${BACKEND_H_IN} ${SMW_BACKEND_H_DIR}/backend.h @ONLY)

# PSA backend header
set(PSA_BACKEND_H_DIR ${CMAKE_CURRENT_BINARY_DIR}/psa_backend)
set(CLI_BACKEND_NAME  "PSA API")
configure_file(${BACKEND_H_IN} ${PSA_BACKEND_H_DIR}/backend.h @ONLY)

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

# Generate SMW hash table at build time (in binary dir)
set(SMW_HASH_TABLE_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/smw_hash_table_generated.c)
set(SMW_NAMES_HEADER ${CMAKE_SOURCE_DIR}/public/smw/names.h)
set(SMW_HASH_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_smw_hash_table.py)

add_custom_command(
    OUTPUT ${SMW_HASH_TABLE_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${SMW_HASH_GENERATOR} ${SMW_HASH_TABLE_SOURCE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${SMW_NAMES_HEADER} ${SMW_HASH_GENERATOR}
    COMMENT "Generating SMW hash table from smw/names.h"
)

# Generate PSA hash table at build time (in binary dir)
set(PSA_HASH_TABLE_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/psa_hash_table_generated.c)
set(PSA_CRYPTO_VALUES_HEADER ${CMAKE_SOURCE_DIR}/public/psa/crypto_values.h)
set(PSA_HASH_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_psa_hash_table.py)

add_custom_command(
    OUTPUT ${PSA_HASH_TABLE_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${PSA_HASH_GENERATOR} ${PSA_HASH_TABLE_SOURCE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${PSA_CRYPTO_VALUES_HEADER} ${PSA_HASH_GENERATOR}
    COMMENT "Generating PSA hash table from psa/crypto_values.h"
)

# Generate hash algorithm enum and common table at build time
set(HASH_ALGO_ENUM_HEADER ${CMAKE_CURRENT_BINARY_DIR}/hash_algo_enum.h)
set(HASH_TABLE_HEADER ${CMAKE_CURRENT_BINARY_DIR}/hash_table_generated.h)
set(HASH_TABLE_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/hash_table_generated.c)
set(HASH_COMMON_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_hash_common_table.py)

add_custom_command(
    OUTPUT
        ${HASH_ALGO_ENUM_HEADER}
        ${HASH_TABLE_HEADER}
        ${HASH_TABLE_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${HASH_COMMON_GENERATOR}
        ${HASH_ALGO_ENUM_HEADER}
        ${HASH_TABLE_HEADER}
        ${HASH_TABLE_SOURCE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${SMW_NAMES_HEADER} ${HASH_COMMON_GENERATOR}
    COMMENT "Generating hash algorithm enum and common table from smw/names.h"
)

# Generate lifecycle table at build time (in binary dir)
set(LIFECYCLE_TABLE_HEADER ${CMAKE_CURRENT_BINARY_DIR}/lifecycle_table.h)
set(LIFECYCLE_TABLE_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/lifecycle_table.c)
set(LIFECYCLE_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_lifecycle_table.py)

add_custom_command(
    OUTPUT
        ${LIFECYCLE_TABLE_HEADER}
        ${LIFECYCLE_TABLE_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${LIFECYCLE_GENERATOR}
        ${LIFECYCLE_TABLE_HEADER}
        ${LIFECYCLE_TABLE_SOURCE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${SMW_NAMES_HEADER} ${LIFECYCLE_GENERATOR}
    COMMENT "Generating lifecycle table from smw/names.h"
)

# Generate symmetric key type table and mappings at build time (in binary dir)
set(SMW_SYM_KEY_MAPPINGS_HEADER ${CMAKE_CURRENT_BINARY_DIR}/smw_sym_key_mappings_generated.h)
set(SMW_SYM_KEY_MAPPINGS_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/smw_sym_key_mappings_generated.c)
set(SMW_ATTR_HEADER ${CMAKE_SOURCE_DIR}/public/smw/attr.h)
set(SMW_SYM_KEY_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_smw_key_sym_table.py)

add_custom_command(
    OUTPUT
        ${SMW_SYM_KEY_MAPPINGS_HEADER}
        ${SMW_SYM_KEY_MAPPINGS_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${SMW_SYM_KEY_GENERATOR} ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${SMW_NAMES_HEADER} ${SMW_ATTR_HEADER} ${SMW_SYM_KEY_GENERATOR}
    COMMENT "Generating SMW key type information table and mappings"
)

# Generate PSA key type mappings at build time (in binary dir)
set(PSA_SYM_KEY_MAPPINGS_HEADER ${CMAKE_CURRENT_BINARY_DIR}/psa_sym_key_mappings_generated.h)
set(PSA_SYM_KEY_MAPPINGS_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/psa_sym_key_mappings_generated.c)
set(PSA_SYM_KEY_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_psa_key_sym_table.py)

add_custom_command(
    OUTPUT
        ${PSA_SYM_KEY_MAPPINGS_HEADER}
        ${PSA_SYM_KEY_MAPPINGS_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${PSA_SYM_KEY_GENERATOR} ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${PSA_CRYPTO_VALUES_HEADER} ${PSA_SYM_KEY_GENERATOR}
    COMMENT "Generating PSA key type and algorithm mappings"
)

# Generate asymmetric key type table and mappings at build time (in binary dir)
set(SMW_ASYM_KEY_MAPPINGS_HEADER ${CMAKE_CURRENT_BINARY_DIR}/smw_asym_key_mappings_generated.h)
set(SMW_ASYM_KEY_MAPPINGS_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/smw_asym_key_mappings_generated.c)
set(ASYM_KEY_TYPE_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_smw_key_asym_table.py)

add_custom_command(
    OUTPUT
        ${SMW_ASYM_KEY_MAPPINGS_HEADER}
        ${SMW_ASYM_KEY_MAPPINGS_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${ASYM_KEY_TYPE_GENERATOR} ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${SMW_NAMES_HEADER} ${SMW_ATTR_HEADER} ${ASYM_KEY_TYPE_GENERATOR}
    COMMENT "Generating SMW asymmetric key type information table and mappings"
)

# Generate PSA asymmetric key type mappings at build time (in binary dir)
set(PSA_ASYM_KEY_MAPPINGS_HEADER ${CMAKE_CURRENT_BINARY_DIR}/psa_asym_key_mappings_generated.h)
set(PSA_ASYM_KEY_MAPPINGS_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/psa_asym_key_mappings_generated.c)
set(PSA_CRYPTO_TYPES_HEADER ${CMAKE_SOURCE_DIR}/public/psa/crypto_types.h)
set(PSA_CRYPTO_VALUES_HEADER ${CMAKE_SOURCE_DIR}/public/psa/crypto_values.h)
set(PSA_ASYM_KEY_MAPPINGS_GENERATOR ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_psa_key_asym_table.py)

add_custom_command(
    OUTPUT
        ${PSA_ASYM_KEY_MAPPINGS_HEADER}
        ${PSA_ASYM_KEY_MAPPINGS_SOURCE}
    COMMAND ${Python3_EXECUTABLE} ${PSA_ASYM_KEY_MAPPINGS_GENERATOR} ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS ${PSA_CRYPTO_TYPES_HEADER} ${PSA_CRYPTO_VALUES_HEADER} ${PSA_ASYM_KEY_MAPPINGS_GENERATOR}
    COMMENT "Generating PSA asymmetric key type information table and mappings"
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
    ${CMAKE_CURRENT_BINARY_DIR}        # For ALL generated files (including headers!)
)

# Executable 1: nxp_smw (SMW API backend)

message(STATUS "Building nxp_smw (SMW API)")

add_executable(nxp_smw
	${CLI_CORE_SOURCES}
	${CLI_SMW_SOURCES}		# SMW-specific implementation
	${SMW_ERROR_HANDLER_SOURCE} 	# Error Table Generated file
	${SMW_HASH_TABLE_SOURCE}	# Hash Table Generated file
	${HASH_TABLE_SOURCE}		# Common Hash Table Generated file
	${LIFECYCLE_TABLE_SOURCE}	# Lifecycle Table Generated file
	${SMW_SYM_KEY_MAPPINGS_SOURCE}	# SMW Key Mappings Generated file
    ${SMW_ASYM_KEY_MAPPINGS_SOURCE}	# SMW Asymmetric Key Mappings Generated file
)

target_include_directories(nxp_smw PRIVATE
    ${CLI_INCLUDE_DIRS}
    ${SMW_BACKEND_H_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/smw
)

target_compile_definitions(nxp_smw PRIVATE USE_SMW_BACKEND)

target_link_libraries(nxp_smw PRIVATE smw)

# Executable 2: nxp_psa (PSA API backend)

message(STATUS "Building nxp_psa (PSA API)")

add_executable(nxp_psa
	${CLI_CORE_SOURCES}
	${CLI_PSA_SOURCES}		# PSA-specific implementation
	${PSA_ERROR_HANDLER_SOURCE} 	# Error Table Generated file
	${PSA_HASH_TABLE_SOURCE}	# Hash Table Generated file
	${HASH_TABLE_SOURCE}		# Common Hash Table Generated file
	${LIFECYCLE_TABLE_SOURCE}	# Lifecycle Table Generated file
    ${PSA_SYM_KEY_MAPPINGS_SOURCE}	# PSA Key Mappings Generated file
    ${PSA_ASYM_KEY_MAPPINGS_SOURCE}
)

target_include_directories(nxp_psa PRIVATE
    ${CLI_INCLUDE_DIRS}
    ${PSA_BACKEND_H_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/psa
)
target_compile_definitions(nxp_psa PRIVATE USE_PSA_BACKEND)

target_link_libraries(nxp_psa PRIVATE smw)

# Installation

install(TARGETS nxp_smw nxp_psa
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT cli-tools)

# Install bash completion script
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/scripts/nxp_smw_completion.bash
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/bash_completion.d
        RENAME nxp_smw
        COMPONENT cli-tools
        OPTIONAL)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/scripts/nxp_psa_completion.bash
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/bash_completion.d
        RENAME nxp_psa
        COMPONENT cli-tools
        OPTIONAL)

# Install CLI test scripts
file(GLOB CLI_TEST_SCRIPTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.sh)

install(PROGRAMS ${CLI_TEST_SCRIPTS}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/smw-cli/tests
        COMPONENT cli-tools)