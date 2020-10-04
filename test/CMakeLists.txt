
llvm_map_components_to_libnames(LLVM_LIBS support core irreader)


add_executable(capstone2llvmirtool
        capstone2llvmtools.cpp
        )

target_compile_features(capstone2llvmirtool PUBLIC cxx_std_17)

target_link_libraries(capstone2llvmirtool
        ${CAPSTONE_LIBRARIES}
        ${KEYSTONE_LIBRARIES}
        ${LLVM_LIBS}
        odec::utils
        odec::capstone2llvmir
        )

set_target_properties(capstone2llvmirtool
        PROPERTIES
        OUTPUT_NAME "odec-capstone2llvmir"
        )
