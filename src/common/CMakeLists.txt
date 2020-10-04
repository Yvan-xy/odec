add_library(common STATIC
        address.cpp
        )
add_library(odec::common ALIAS common)

target_compile_features(common PUBLIC cxx_std_17)

target_include_directories(common
        PUBLIC
        $<BUILD_INTERFACE:${ODEC_INCLUDE_DIR}>
        )

target_link_libraries(common
        PRIVATE
        odec::utils
        )

set_target_properties(common
        PROPERTIES
        OUTPUT_NAME "odec-common"
        )