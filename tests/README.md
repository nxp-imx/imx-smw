# How to use SMW test engine

## Using CTest
Execute the following commands:
```
$ cd /home/smw/tests
$ ctest
```
Some CTest options:
```
--verbose to print debug messages
-R <test_name> to run only <test_name> test
-L <label_name> to run <label_name> tests
```

## Using test executable
Execute the following commands:
```
$ export SMW_CONFIG_FILE=/path/to/SMW Configuration file
$ /usr/bin/<executable_name> [options]
```
Executable options are listed using the `-h` option.

# Install directories
CTestTestfile.cmake and temporary CTest files are located in:
`/home/smw/tests`
This is also the default directory for test status file.

Tests executable are located in:
`/usr/bin`

Tests required files are located in:
`/usr/share/smw/tests`

- `/config` for SMW configurations files
- `/test_definition` for test definition files
- `/scripts` for test scripts

# Source tree
`cmake`: Directory containing CMake scripts
`config`: Directory containing SMW configuration files
`engine`: Directory containing test engine sources and includes files
`scripts`: Directory containing scripts run by ctest
`test_definition`: Directory containing tests definition files (JSON format)
`CMakeLists.txt`: CMake configuration file to build tests
`README.md`
