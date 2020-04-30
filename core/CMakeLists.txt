include(add_component)

set(CORE_SRC_INC ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(CORE_BIN_INC ${CMAKE_CURRENT_BINARY_DIR}/inc)
set(INCLUDE_DIR ${INCLUDE_DIR} ${CORE_SRC_INC} ${CORE_BIN_INC})

set(LIST_SUBSYSTEM_ID)
set(LIST_SUBSYSTEM_EXPORT)
set(LIST_SUBSYSTEM_NAME)
set(LIST_SUBSYSTEM_FUNC)
set(SUBSYSTEM_ID SUBSYSTEM_ID)
set(ENUM_SUBSYSTEM_ID "enum subsystem_id")
set(STRUCT_SUBSYSTEM_FUNC "struct subsystem_func")
set(RETURN_SUBSYSTEM_FUNC "${STRUCT_SUBSYSTEM_FUNC} \*")

set(LIST_OPERATION_ID)
set(LIST_OPERATION_EXPORT)
set(LIST_OPERATION_NAME)
set(LIST_OPERATION_FUNC)
set(OPERATION_ID OPERATION_ID)
set(ENUM_OPERATION_ID "enum operation_id")
set(STRUCT_OPERATION_FUNC "struct operation_func")
set(RETURN_OPERATION_FUNC "${STRUCT_OPERATION_FUNC} \*")

macro(add_subsystem subsystem)
    add_component(${subsystem} SUBSYSTEM_ID RETURN_SUBSYSTEM_FUNC
                  LIST_SUBSYSTEM_ID
                  LIST_SUBSYSTEM_EXPORT
                  LIST_SUBSYSTEM_NAME
                  LIST_SUBSYSTEM_FUNC)
    set(LIST_SUBSYSTEM_ID ${LIST_SUBSYSTEM_ID} PARENT_SCOPE)
    set(LIST_SUBSYSTEM_EXPORT ${LIST_SUBSYSTEM_EXPORT} PARENT_SCOPE)
    set(LIST_SUBSYSTEM_NAME ${LIST_SUBSYSTEM_NAME} PARENT_SCOPE)
    set(LIST_SUBSYSTEM_FUNC ${LIST_SUBSYSTEM_FUNC} PARENT_SCOPE)

    add_subdirectory(${subsystem})
endmacro()

macro(add_operation operation)
    add_component(${operation} OPERATION_ID RETURN_OPERATION_FUNC
                  LIST_OPERATION_ID
                  LIST_OPERATION_EXPORT
                  LIST_OPERATION_NAME
                  LIST_OPERATION_FUNC)
    set(LIST_OPERATION_ID ${LIST_OPERATION_ID} PARENT_SCOPE)
    set(LIST_OPERATION_EXPORT ${LIST_OPERATION_EXPORT} PARENT_SCOPE)
    set(LIST_OPERATION_NAME ${LIST_OPERATION_NAME} PARENT_SCOPE)
    set(LIST_OPERATION_FUNC ${LIST_OPERATION_FUNC} PARENT_SCOPE)
endmacro()

add_subdirectory(utils)
add_subdirectory(init)
add_subdirectory(subsystems)
add_subdirectory(keymgr)
add_subdirectory(crypto)
#[[The subdirectory config must be the last one to be added because
config/CMakeLists.txt calls configure_file() that requires cache variables
that are set by several CMakeLists.txt from the subdirectories above.]]
add_subdirectory(config)

configure_file(${CORE_SRC_INC}/operations.h.in ${CORE_BIN_INC}/operations.h)
configure_file(${CORE_SRC_INC}/subsystems.h.in ${CORE_BIN_INC}/subsystems.h)

set(OBJ_LIST ${OBJ_LIST} PARENT_SCOPE)
