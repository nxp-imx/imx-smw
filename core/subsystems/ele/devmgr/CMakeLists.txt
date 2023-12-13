get_filename_component(folder ${CMAKE_CURRENT_SOURCE_DIR} NAME)
file(TO_NATIVE_PATH "${folder}/" folder)

list(APPEND folder_files
            devmgr.c
            sign_message.c
            $<$<BOOL:${ENABLE_DEVICE_ATTESTATION}>:attestation.c>
            $<$<BOOL:${ENABLE_DEVICE_LIFECYCLE}>:lifecycle.c>
            $<$<BOOL:${ENABLE_DEVICE_REPROVISION}>:reprovisioning.c>)

list(TRANSFORM folder_files PREPEND "${folder}")
list(APPEND ele_srcs ${folder_files})
set(ele_srcs ${ele_srcs} PARENT_SCOPE)