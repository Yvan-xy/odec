
add_library(capstone2llvmir STATIC
        x86/x86_init.cpp
        x86/x86.cpp
        capstone2llvmir_impl.cpp
        capstone2llvmir.cpp
        exceptions.cpp
        llvmir_utils.cpp
        )
add_library(odec::capstone2llvmir ALIAS capstone2llvmir)

target_compile_features(capstone2llvmir PUBLIC cxx_std_17)

target_include_directories(capstone2llvmir
        PUBLIC
        $<BUILD_INTERFACE:${ODEC_INCLUDE_DIR}>
        $<BUILD_INTERFACE:${ODEC_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${ODEC_INSTALL_INCLUDE_DIR}>
        )

target_link_libraries(capstone2llvmir
        PUBLIC
        odec::common
        ${CAPSTONE_LIBRARIES}
        )

set_target_properties(capstone2llvmir
        PROPERTIES
        OUTPUT_NAME "retdec-capstone2llvmir"
        )

# Install libs.
install(TARGETS capstone2llvmir
        EXPORT capstone2llvmir-targets
        ARCHIVE DESTINATION ${ODEC_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${ODEC_INSTALL_LIB_DIR}
        )
