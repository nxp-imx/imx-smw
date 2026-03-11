# Collect all source files in smw/
file(GLOB SMW_SOURCES *.c)

# Export to parent scope
set(CLI_SMW_SOURCES ${SMW_SOURCES} PARENT_SCOPE)