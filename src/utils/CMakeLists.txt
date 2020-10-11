
add_library(utils STATIC
        crc32.cpp
        time.cpp
        string.cpp
        conversion.cpp
        io/log.cpp
        io/logger.cpp
        )
add_library(odec::utils ALIAS utils)

target_compile_features(utils PUBLIC cxx_std_17)

target_include_directories(utils
        PUBLIC
        $<BUILD_INTERFACE:${ODEC_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:${ODEC_INSTALL_INCLUDE_DIR}>
        )

# We may need to link filesystem library manually.
find_library(STD_CPP_FS stdc++fs)
# Library found -> link against it.
if (STD_CPP_FS)
    message(STATUS "-- Library stdc++fs found -> Linking with ${STD_CPP_FS}")
    target_link_libraries(utils
            PRIVATE
            stdc++fs
            )
    # Library not found & (Linux, BSD, Solaris, Minix) & GCC
elseif (UNIX AND (NOT APPLE) AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(STATUS "-- Library stdc++fs NOT found & Linux+GCC -> Linking with stdc++fs")
    target_link_libraries(utils
            PRIVATE
            stdc++fs
            )
    # Library not found -> hope compiler does not need it.
else ()
    message(STATUS "-- Library stdc++fs NOT found -> linking utils without stdc++fs library")
endif ()

# Disable the min() and max() macros to prevent errors when using e.g.
# std::numeric_limits<...>::max()
# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
# Any target that includes "windows.h" needs to define this.
if (MSVC)
    target_compile_definitions(utils PUBLIC NOMINMAX)
endif ()

set_target_properties(utils
        PROPERTIES
        OUTPUT_NAME "odec-utils"
        )
