####
# FPrime CMakeLists.txt:
#
# SOURCE_FILES: combined list of source and autocoding files
# MOD_DEPS: (optional) module dependencies
# UT_SOURCE_FILES: list of source files for unit tests
#
# More information in the F´ CMake API documentation:
# https://fprime.jpl.nasa.gov/latest/documentation/reference
#
####

set(SOURCE_FILES
  "${CMAKE_CURRENT_LIST_DIR}/AsconEncryptor.fpp"
  "${CMAKE_CURRENT_LIST_DIR}/AsconEncryptor.cpp"
)

# In /home/aaron/fprime/ASCON/Components/AsconEncryptor/CMakeLists.txt
add_subdirectory(
    "${CMAKE_CURRENT_LIST_DIR}/../../lib/ASCON"

    "${CMAKE_CURRENT_BINARY_DIR}/ascon_lib"
)


# Uncomment and add any modules that this component depends on, else
# they might not be available when cmake tries to build this component.
#
# Module names are derived from the path from the nearest project/library/framework
# root when not specifically overridden by the developer. i.e. The module defined by
# `Ref/SignalGen/CMakeLists.txt` will be named `Ref_SignalGen`.  `Ref/SignalGen`
# is an acceptable alternative and will be internally converted to `Ref_SignalGen`.
#
# Now tell F´ to link the `ascon` library
# by declaring it in `MOD_DEPS`.
# (This is how fprime-util knows to link them.)

set(MOD_DEPS
  ascon
  # plus any other F´ or user modules you depend on
)

register_fprime_module()


### Unit Tests ###
# set(UT_SOURCE_FILES
#   "${CMAKE_CURRENT_LIST_DIR}/AsconEncryptor.fpp"
#   "${CMAKE_CURRENT_LIST_DIR}/test/ut/AsconEncryptorTestMain.cpp"
#   "${CMAKE_CURRENT_LIST_DIR}/test/ut/AsconEncryptorTester.cpp"
# )
# set(UT_MOD_DEPS
#   STest
# )
# set(UT_AUTO_HELPERS ON)
# register_fprime_ut()
