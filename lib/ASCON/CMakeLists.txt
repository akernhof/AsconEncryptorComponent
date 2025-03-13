# /home/aaron/fprime/ASCON/lib/ASCON/CMakeLists.txt

# Create a static library from Ascon sources
add_library(ascon STATIC
    aead.c
    printstate.c  # optional
    # ... add other .c files if needed
)

# So #include "api.h", etc. works
target_include_directories(ascon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
