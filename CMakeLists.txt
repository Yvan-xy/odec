cmake_minimum_required(VERSION 3.17)
project(odec)


set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


set(ODEC_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(ODEC_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
message(STATUS "Cmake install Bin Dir ${CMAKE_INSTALL_LIBDIR}")

include_directories(${ODEC_INCLUDE_DIR})

# ==================== Dependence =======================
# Add capstone
include(FindPkgConfig)
# Use CAPSTONE_FOUND, CAPSTONE_LIBRARIES, CAPSTONE_INCLUDE_DIRS vars
pkg_check_modules(CAPSTONE REQUIRED capstone)
include_directories(${CAPSTONE_INCLUDE_DIRS}/../)
message(STATUS "Found capstone ${CAPSTONE_FOUND}")
message(STATUS "Capstone library is ${CAPSTONE_LIBRARIES}")
add_library(capstone SHARED IMPORTED)
set_target_properties(
        capstone
        PROPERTIES IMPORTED_LOCATION
        /usr/local/opt/capstone/lib/libcapstone.dylib
)

# Add keystone
pkg_check_modules(KEYSTONE REQUIRED keystone)
include_directories(${KEYSTONE_INCLUDE_DIRS})

message(STATUS "Found keystone ${KEYSTONE_FOUND}")
message(STATUS "Keystone include path is ${KEYSTONE_INCLUDE_DIRS}")

add_library(keystone SHARED IMPORTED)
set_target_properties(
        keystone
        PROPERTIES IMPORTED_LOCATION
        /usr/local/opt/keystone/lib/libkeystone.a
)

# Add LLVM
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# ========================================================

file(GLOB_RECURSE SOURCES "${ODEC_SOURCE_DIR}/*.cpp")
add_executable(odec main.cpp)
target_link_libraries(odec ${CAPSTONE_LIBRARIES} ${KEYSTONE_LIBRARIES})

add_subdirectory(test)
add_subdirectory(src)

