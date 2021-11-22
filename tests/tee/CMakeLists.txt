find_package(TA_dev_kit REQUIRED)

string(REGEX REPLACE "-gcc$" "-" CROSS_COMPILE  ${CMAKE_C_COMPILER})

add_subdirectory(ta)
