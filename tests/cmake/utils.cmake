#
# Notes:
# CMake function() is used when output variable(s) is(are) updated
# CMake macro() is used when there is(are) no variable(s) to update
#

set(tests_list_separator "/")
set(def_file_extension ".json")

#
# get_test() - Get test name and test definition file name
# @definition_file: [Input] Test definition file
# @out_name: [Output] Test name
# @out_test_definition: [Output] Test definition file without path prefix
#
function(get_test definition_file out_name out_test_definition)
	# Extract file path
	get_filename_component(test_definition ${definition_file} NAME)

	# Update output test definition name
	set(${out_test_definition} ${test_definition} PARENT_SCOPE)

	# Extract file path and file extension
	get_filename_component(test_name ${definition_file} NAME_WE)

	# Update output test name
	set(${out_name} ${test_name} PARENT_SCOPE)
endfunction()

#
# get_labels_list() - Return a list of labels
# @tname: [Input] Test name
# @out_list: [Output] List of labels
#
# Return the list of labels of the test defined by @tname.
#
function(get_labels_list tname out_list)
	# Convert tname string in a list
	set(tname_list ${tname})
	string(REGEX REPLACE "_" ";" tname_list ${tname_list})

	#
	# Create a sublist without the last element of the tname_list (last part
	# of the test name is the test number which is not part of the list of
	# labels)
	#
	list(REMOVE_AT tname_list -1)

	# Update output list of labels
	set(${out_list} ${tname_list} PARENT_SCOPE)
endfunction()

#
# get_tests_list() - Return a tests list
# @definition_list: [Input] List of test definition files
# @out_test_list: [Output] Tests list
#
# A tests list is a list defined as follow:
# "testname(1);definition_file_name(1);...;definition_file_name(1n);/.../
# testname(n);definition_file_name(n1);...;definition_file_name(nn)"
# Each test name is followed by the definition files names associted to it.
# Tests are separated by the @tests_list_separator character.
#
# Tests list is built from the contents of @definition_list.
#
function(get_tests_list definition_list out_test_list)
	list(SORT definition_list)
	foreach(file ${definition_list})
		get_test(${file} testname testdefinition)
		list(FIND tests_list ${testname} idx)

		#
		# If the test is not present in the list add the following
		# elements: testname;test_definition_file;/
		# Else, add the other test definition file at the right place.
		#
		if (${idx} EQUAL -1)
			list(APPEND tests_list ${testname} ${testdefinition}
			${tests_list_separator})
		else()
			#
			# Test name is the last in list (list is sorted
			# alphabetically)
			#
			list(INSERT tests_list -1 ${testdefinition})
		endif()
	endforeach()

	# Update output tests list
	set(${out_test_list} ${tests_list} PARENT_SCOPE)
endfunction()

#
# pop_front_list() - Extract the first element of a list
# @list: [Input] List
# @out_list: [Output] Output list
# @out_value: [Output] Extracted element
#
# @out_value is set to @list first element.
# @list first element is removed.
# @out_list is set to the new list, i.e @list without the first element.
#
function(pop_front_list list out_list out_value)
	if (${CMAKE_VERSION} VERSION_GREATER_EQUAL 3.15)
		list(POP_FRONT list tmp_value)
	else()
		list(GET list 0 tmp_value)
		list(REMOVE_AT list 0)
	endif()

	set(${out_list} ${list} PARENT_SCOPE)
	set(${out_value} ${tmp_value} PARENT_SCOPE)
endfunction()

#
# add_tests() - Add tests to the project
# @definition_list: [Input] List of test definition files
# @cmd: [Input] Test command common to all tests
#
# Test definition file extension is @def_file_extension.
# Test commands use test definition files located in
# SMW_TESTS_TARGET_DEF_DIR_FULL_PATH.
#
macro(add_tests definition_list cmd)
	# Get test list
	get_tests_list("${definition_list}" testslist)

	while(testslist)
		set(test_cmd ${cmd})

		# Get test name
		pop_front_list("${testslist}" testslist test_name)

		# Add all test definition files to the command
		pop_front_list("${testslist}" testslist tmp)
		while(NOT ${tmp} STREQUAL ${tests_list_separator})
			list(APPEND test_cmd
			     "${SMW_TESTS_TARGET_DEF_DIR_FULL_PATH}/${tmp}")
			pop_front_list("${testslist}" testslist tmp)
		endwhile()

		# Get label list
		get_labels_list(${test_name} labels_list)

		# Add test
		add_test(NAME ${test_name} COMMAND ${test_cmd})
		set_tests_properties(${test_name} PROPERTIES LABELS
				     "${labels_list}")
	endwhile()
endmacro()

#
# add_and_install_tests() - Add tests to the project and install test definition
#                           files
# @def_list: [Input] List of test definition files.
# @cfg_list: [Input] List of test configuration files.
# @cmd: [Input] Test command common to all tests.
#
macro(add_and_install_tests def_list cfg_list cmd)
	add_tests("${def_list}" "${cmd}")

	# Install the test definition files
	install(FILES ${def_list}
		DESTINATION ${SMW_TESTS_TARGET_DEF_DIR}
		EXCLUDE_FROM_ALL
		COMPONENT ${PROJECT_NAME})

	# Install the test configuration files
	install(FILES ${cfg_list}
		DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR}
		EXCLUDE_FROM_ALL
		COMPONENT ${PROJECT_NAME})
endmacro()
