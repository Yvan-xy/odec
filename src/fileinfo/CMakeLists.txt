#-------------------------------- odec-fileinfo ----------------------------------
add_executable(fileinfo
        fileinfo.cpp
        util/crypto.cpp
        util/format_detector.cpp
        fileformat/section/section.cpp
        )


target_compile_features(fileinfo PUBLIC cxx_std_17)

target_include_directories(fileinfo
        PUBLIC
        $<BUILD_INTERFACE:${ODEC_INCLUDE_DIR}>
        )
target_link_libraries(fileinfo
        odec::utils
        odec::common
        OpenSSL::SSL
        )

set_target_properties(fileinfo
        PROPERTIES
        OUTPUT_NAME "odec-fileinfo"
        )

#-------------------------------- libodec-fileinfo ----------------------------------
add_library(fileinfolib STATIC
        fileinfo.cpp
        util/crypto.cpp
        util/format_detector.cpp
        fileformat/section/section.cpp
        )
target_compile_features(fileinfolib PUBLIC cxx_std_17)

add_library(odec::fileinfolib ALIAS fileinfolib)
target_include_directories(fileinfolib
        PUBLIC
        $<BUILD_INTERFACE:${ODEC_INCLUDE_DIR}>
        )

target_link_libraries(fileinfolib
        odec::utils
        odec::common
        OpenSSL::SSL
        )

set_target_properties(fileinfolib
        PROPERTIES
        OUTPUT_NAME "odec-fileinfo"
        )