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
CMAKE_SOURCE_DIR = "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/cmake-build-debug"

# Include any dependencies generated for this target.
include CMakeFiles/Ex4_Tikchoret.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Ex4_Tikchoret.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Ex4_Tikchoret.dir/flags.make

CMakeFiles/Ex4_Tikchoret.dir/main.c.o: CMakeFiles/Ex4_Tikchoret.dir/flags.make
CMakeFiles/Ex4_Tikchoret.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/Ex4_Tikchoret.dir/main.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/Ex4_Tikchoret.dir/main.c.o   -c "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/main.c"

CMakeFiles/Ex4_Tikchoret.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Ex4_Tikchoret.dir/main.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/main.c" > CMakeFiles/Ex4_Tikchoret.dir/main.c.i

CMakeFiles/Ex4_Tikchoret.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Ex4_Tikchoret.dir/main.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/main.c" -o CMakeFiles/Ex4_Tikchoret.dir/main.c.s

# Object files for target Ex4_Tikchoret
Ex4_Tikchoret_OBJECTS = \
"CMakeFiles/Ex4_Tikchoret.dir/main.c.o"

# External object files for target Ex4_Tikchoret
Ex4_Tikchoret_EXTERNAL_OBJECTS =

Ex4_Tikchoret: CMakeFiles/Ex4_Tikchoret.dir/main.c.o
Ex4_Tikchoret: CMakeFiles/Ex4_Tikchoret.dir/build.make
Ex4_Tikchoret: CMakeFiles/Ex4_Tikchoret.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable Ex4_Tikchoret"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Ex4_Tikchoret.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Ex4_Tikchoret.dir/build: Ex4_Tikchoret

.PHONY : CMakeFiles/Ex4_Tikchoret.dir/build

CMakeFiles/Ex4_Tikchoret.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Ex4_Tikchoret.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Ex4_Tikchoret.dir/clean

CMakeFiles/Ex4_Tikchoret.dir/depend:
	cd "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/cmake-build-debug" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret" "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret" "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/cmake-build-debug" "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/cmake-build-debug" "/Users/nathanaelbenichou/Desktop/M4 Tikchorette/Ex4-Tikchoret/cmake-build-debug/CMakeFiles/Ex4_Tikchoret.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/Ex4_Tikchoret.dir/depend
