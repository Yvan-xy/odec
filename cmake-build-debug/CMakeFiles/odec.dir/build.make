# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/dyf/code/solo/odec

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/dyf/code/solo/odec/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/odec.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/odec.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/odec.dir/flags.make

CMakeFiles/odec.dir/main.cpp.o: CMakeFiles/odec.dir/flags.make
CMakeFiles/odec.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/dyf/code/solo/odec/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/odec.dir/main.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/odec.dir/main.cpp.o -c /Users/dyf/code/solo/odec/main.cpp

CMakeFiles/odec.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/odec.dir/main.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dyf/code/solo/odec/main.cpp > CMakeFiles/odec.dir/main.cpp.i

CMakeFiles/odec.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/odec.dir/main.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dyf/code/solo/odec/main.cpp -o CMakeFiles/odec.dir/main.cpp.s

# Object files for target odec
odec_OBJECTS = \
"CMakeFiles/odec.dir/main.cpp.o"

# External object files for target odec
odec_EXTERNAL_OBJECTS =

odec: CMakeFiles/odec.dir/main.cpp.o
odec: CMakeFiles/odec.dir/build.make
odec: /usr/local/opt/capstone/lib/libcapstone.dylib
odec: /usr/local/opt/keystone/lib/libkeystone.a
odec: CMakeFiles/odec.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/dyf/code/solo/odec/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable odec"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/odec.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/odec.dir/build: odec

.PHONY : CMakeFiles/odec.dir/build

CMakeFiles/odec.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/odec.dir/cmake_clean.cmake
.PHONY : CMakeFiles/odec.dir/clean

CMakeFiles/odec.dir/depend:
	cd /Users/dyf/code/solo/odec/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/dyf/code/solo/odec /Users/dyf/code/solo/odec /Users/dyf/code/solo/odec/cmake-build-debug /Users/dyf/code/solo/odec/cmake-build-debug /Users/dyf/code/solo/odec/cmake-build-debug/CMakeFiles/odec.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/odec.dir/depend
