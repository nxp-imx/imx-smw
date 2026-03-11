# Collect all source files in core/
file(GLOB CORE_SOURCES *.c)

# Export to parent scope
set(CLI_CORE_SOURCES ${CORE_SOURCES} PARENT_SCOPE)