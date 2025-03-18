# Include project-wide components here

# add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/MyComponent")
add_subdirectory(
    "${CMAKE_CURRENT_LIST_DIR}/../lib/ASCON"

    "${CMAKE_CURRENT_BINARY_DIR}/ascon_lib"
)

add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/AsconEncryptor/")
add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/WifiHandler/")
add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/WifiReceiver/")
