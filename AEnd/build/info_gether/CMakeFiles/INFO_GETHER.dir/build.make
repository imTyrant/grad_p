# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/imt/grad_p/workspace/project

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/imt/grad_p/workspace/project/build

# Include any dependencies generated for this target.
include info_gether/CMakeFiles/INFO_GETHER.dir/depend.make

# Include the progress variables for this target.
include info_gether/CMakeFiles/INFO_GETHER.dir/progress.make

# Include the compile flags for this target's objects.
include info_gether/CMakeFiles/INFO_GETHER.dir/flags.make

info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o: info_gether/CMakeFiles/INFO_GETHER.dir/flags.make
info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o: ../info_gether/info_gether.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/imt/grad_p/workspace/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o"
	cd /home/imt/grad_p/workspace/project/build/info_gether && /usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/INFO_GETHER.dir/info_gether.cc.o -c /home/imt/grad_p/workspace/project/info_gether/info_gether.cc

info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/INFO_GETHER.dir/info_gether.cc.i"
	cd /home/imt/grad_p/workspace/project/build/info_gether && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/imt/grad_p/workspace/project/info_gether/info_gether.cc > CMakeFiles/INFO_GETHER.dir/info_gether.cc.i

info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/INFO_GETHER.dir/info_gether.cc.s"
	cd /home/imt/grad_p/workspace/project/build/info_gether && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/imt/grad_p/workspace/project/info_gether/info_gether.cc -o CMakeFiles/INFO_GETHER.dir/info_gether.cc.s

info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.requires:

.PHONY : info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.requires

info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.provides: info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.requires
	$(MAKE) -f info_gether/CMakeFiles/INFO_GETHER.dir/build.make info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.provides.build
.PHONY : info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.provides

info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.provides.build: info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o


# Object files for target INFO_GETHER
INFO_GETHER_OBJECTS = \
"CMakeFiles/INFO_GETHER.dir/info_gether.cc.o"

# External object files for target INFO_GETHER
INFO_GETHER_EXTERNAL_OBJECTS =

info_gether/libINFO_GETHER.a: info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o
info_gether/libINFO_GETHER.a: info_gether/CMakeFiles/INFO_GETHER.dir/build.make
info_gether/libINFO_GETHER.a: info_gether/CMakeFiles/INFO_GETHER.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/imt/grad_p/workspace/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libINFO_GETHER.a"
	cd /home/imt/grad_p/workspace/project/build/info_gether && $(CMAKE_COMMAND) -P CMakeFiles/INFO_GETHER.dir/cmake_clean_target.cmake
	cd /home/imt/grad_p/workspace/project/build/info_gether && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/INFO_GETHER.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
info_gether/CMakeFiles/INFO_GETHER.dir/build: info_gether/libINFO_GETHER.a

.PHONY : info_gether/CMakeFiles/INFO_GETHER.dir/build

info_gether/CMakeFiles/INFO_GETHER.dir/requires: info_gether/CMakeFiles/INFO_GETHER.dir/info_gether.cc.o.requires

.PHONY : info_gether/CMakeFiles/INFO_GETHER.dir/requires

info_gether/CMakeFiles/INFO_GETHER.dir/clean:
	cd /home/imt/grad_p/workspace/project/build/info_gether && $(CMAKE_COMMAND) -P CMakeFiles/INFO_GETHER.dir/cmake_clean.cmake
.PHONY : info_gether/CMakeFiles/INFO_GETHER.dir/clean

info_gether/CMakeFiles/INFO_GETHER.dir/depend:
	cd /home/imt/grad_p/workspace/project/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/imt/grad_p/workspace/project /home/imt/grad_p/workspace/project/info_gether /home/imt/grad_p/workspace/project/build /home/imt/grad_p/workspace/project/build/info_gether /home/imt/grad_p/workspace/project/build/info_gether/CMakeFiles/INFO_GETHER.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : info_gether/CMakeFiles/INFO_GETHER.dir/depend

