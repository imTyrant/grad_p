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
include aik_init/CMakeFiles/AIK_INIT.dir/depend.make

# Include the progress variables for this target.
include aik_init/CMakeFiles/AIK_INIT.dir/progress.make

# Include the compile flags for this target's objects.
include aik_init/CMakeFiles/AIK_INIT.dir/flags.make

aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o: aik_init/CMakeFiles/AIK_INIT.dir/flags.make
aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o: ../aik_init/aik_init.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/imt/grad_p/workspace/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o"
	cd /home/imt/grad_p/workspace/project/build/aik_init && /usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/AIK_INIT.dir/aik_init.cc.o -c /home/imt/grad_p/workspace/project/aik_init/aik_init.cc

aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/AIK_INIT.dir/aik_init.cc.i"
	cd /home/imt/grad_p/workspace/project/build/aik_init && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/imt/grad_p/workspace/project/aik_init/aik_init.cc > CMakeFiles/AIK_INIT.dir/aik_init.cc.i

aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/AIK_INIT.dir/aik_init.cc.s"
	cd /home/imt/grad_p/workspace/project/build/aik_init && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/imt/grad_p/workspace/project/aik_init/aik_init.cc -o CMakeFiles/AIK_INIT.dir/aik_init.cc.s

aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.requires:

.PHONY : aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.requires

aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.provides: aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.requires
	$(MAKE) -f aik_init/CMakeFiles/AIK_INIT.dir/build.make aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.provides.build
.PHONY : aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.provides

aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.provides.build: aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o


# Object files for target AIK_INIT
AIK_INIT_OBJECTS = \
"CMakeFiles/AIK_INIT.dir/aik_init.cc.o"

# External object files for target AIK_INIT
AIK_INIT_EXTERNAL_OBJECTS =

aik_init/libAIK_INIT.a: aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o
aik_init/libAIK_INIT.a: aik_init/CMakeFiles/AIK_INIT.dir/build.make
aik_init/libAIK_INIT.a: aik_init/CMakeFiles/AIK_INIT.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/imt/grad_p/workspace/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libAIK_INIT.a"
	cd /home/imt/grad_p/workspace/project/build/aik_init && $(CMAKE_COMMAND) -P CMakeFiles/AIK_INIT.dir/cmake_clean_target.cmake
	cd /home/imt/grad_p/workspace/project/build/aik_init && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/AIK_INIT.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
aik_init/CMakeFiles/AIK_INIT.dir/build: aik_init/libAIK_INIT.a

.PHONY : aik_init/CMakeFiles/AIK_INIT.dir/build

aik_init/CMakeFiles/AIK_INIT.dir/requires: aik_init/CMakeFiles/AIK_INIT.dir/aik_init.cc.o.requires

.PHONY : aik_init/CMakeFiles/AIK_INIT.dir/requires

aik_init/CMakeFiles/AIK_INIT.dir/clean:
	cd /home/imt/grad_p/workspace/project/build/aik_init && $(CMAKE_COMMAND) -P CMakeFiles/AIK_INIT.dir/cmake_clean.cmake
.PHONY : aik_init/CMakeFiles/AIK_INIT.dir/clean

aik_init/CMakeFiles/AIK_INIT.dir/depend:
	cd /home/imt/grad_p/workspace/project/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/imt/grad_p/workspace/project /home/imt/grad_p/workspace/project/aik_init /home/imt/grad_p/workspace/project/build /home/imt/grad_p/workspace/project/build/aik_init /home/imt/grad_p/workspace/project/build/aik_init/CMakeFiles/AIK_INIT.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : aik_init/CMakeFiles/AIK_INIT.dir/depend

