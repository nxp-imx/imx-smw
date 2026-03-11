# Collect all source files in psa/
file(GLOB PSA_SOURCES *.c)

# Export to parent scope
set(CLI_PSA_SOURCES ${PSA_SOURCES} PARENT_SCOPE)
