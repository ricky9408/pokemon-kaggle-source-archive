cmake_minimum_required(VERSION 3.20)
project(v631302_m0_diagnostic_relaxed_fixture LANGUAGES CXX)

# This is a separate, explicitly nonconforming emulation fixture.  It must not
# be added to the strict collector's CMake project: strict recipe and binary
# identity are independently preserved outside this build graph.
find_package(LLVM 16.0.6 REQUIRED CONFIG)
find_package(Clang 16.0.6 REQUIRED CONFIG)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(V631302_RELAXED_BUNDLE_INIT_PATH "" CACHE FILEPATH
    "Absolute path to the zero-byte canonicalizer package initializer")
set(V631302_RELAXED_BUNDLE_ENTRY_PATH "" CACHE FILEPATH
    "Absolute path to m0_diagnostic_census.py")
set(V631302_RELAXED_BUNDLE_PRIMITIVES_PATH "" CACHE FILEPATH
    "Absolute path to m0_diagnostic_primitives.py")
set(V631302_RELAXED_BUNDLE_WORKER_PATH "" CACHE FILEPATH
    "Absolute path to v631302_diagnostic_worker_v1.py")
set(V631302_RELAXED_RAW_COLLECTOR_SIZE "" CACHE STRING
    "Exact byte length of the bound raw collector capture")
set(V631302_RELAXED_RAW_COLLECTOR_SHA256 "" CACHE STRING
    "Exact SHA-256 of the bound raw collector capture")
set(V631302_RELAXED_RAW_COLLECTOR_CAPTURE_ROOT "" CACHE STRING
    "Exact RAW_COLLECTOR_CAPTURE_V1 root bound into this build")

foreach(V631302_RELAXED_REQUIRED_PATH IN ITEMS
        V631302_RELAXED_BUNDLE_INIT_PATH
        V631302_RELAXED_BUNDLE_ENTRY_PATH
        V631302_RELAXED_BUNDLE_PRIMITIVES_PATH
        V631302_RELAXED_BUNDLE_WORKER_PATH)
    if(NOT IS_ABSOLUTE "${${V631302_RELAXED_REQUIRED_PATH}}" OR
       NOT EXISTS "${${V631302_RELAXED_REQUIRED_PATH}}")
        message(FATAL_ERROR "${V631302_RELAXED_REQUIRED_PATH} must name an existing absolute file")
    endif()
endforeach()

if(NOT V631302_RELAXED_RAW_COLLECTOR_SIZE MATCHES "^[1-9][0-9]*$" OR
   V631302_RELAXED_RAW_COLLECTOR_SIZE GREATER 67108864)
    message(FATAL_ERROR
        "V631302_RELAXED_RAW_COLLECTOR_SIZE must be in [1,67108864]")
endif()
foreach(V631302_RELAXED_RAW_DIGEST IN ITEMS
        V631302_RELAXED_RAW_COLLECTOR_SHA256
        V631302_RELAXED_RAW_COLLECTOR_CAPTURE_ROOT)
    string(LENGTH "${${V631302_RELAXED_RAW_DIGEST}}" V631302_RELAXED_RAW_DIGEST_LENGTH)
    if(NOT V631302_RELAXED_RAW_DIGEST_LENGTH EQUAL 64 OR
       NOT "${${V631302_RELAXED_RAW_DIGEST}}" MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR "${V631302_RELAXED_RAW_DIGEST} must be a lowercase SHA-256")
    endif()
endforeach()

# Amendment 9 requires the V2 structural-path and definition-instance identity
# canonicalizer. This working identity remains zero-authority and fail-closed.
set(V631302_RELAXED_INIT_SIZE 0)
set(V631302_RELAXED_INIT_SHA256
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
set(V631302_RELAXED_ENTRY_SIZE 43366)
set(V631302_RELAXED_ENTRY_SHA256
    "1c379cef095a7be4cab4d0ca3eb083ffcd3b9f3bfc35201d1d39aaa88dda558e")
set(V631302_RELAXED_PRIMITIVES_SIZE 20056)
set(V631302_RELAXED_PRIMITIVES_SHA256
    "226b7ef26df5a78c8eb264acba84c3488c40916a6316834a0cbf425f36ca2333")
set(V631302_RELAXED_WORKER_SIZE 33817)
set(V631302_RELAXED_WORKER_SHA256
    "0dcbb36e1993a0b9192ed5178eefe5c3746efbe348ab6800a64cd4b8bdd6795a")

foreach(V631302_RELAXED_MEMBER IN ITEMS INIT ENTRY PRIMITIVES WORKER)
    file(SIZE "${V631302_RELAXED_BUNDLE_${V631302_RELAXED_MEMBER}_PATH}"
         V631302_RELAXED_OBSERVED_${V631302_RELAXED_MEMBER}_SIZE)
    file(SHA256 "${V631302_RELAXED_BUNDLE_${V631302_RELAXED_MEMBER}_PATH}"
         V631302_RELAXED_OBSERVED_${V631302_RELAXED_MEMBER}_SHA256)
    if(NOT V631302_RELAXED_OBSERVED_${V631302_RELAXED_MEMBER}_SIZE EQUAL
       V631302_RELAXED_${V631302_RELAXED_MEMBER}_SIZE OR
       NOT V631302_RELAXED_OBSERVED_${V631302_RELAXED_MEMBER}_SHA256 STREQUAL
           V631302_RELAXED_${V631302_RELAXED_MEMBER}_SHA256)
        message(FATAL_ERROR
            "${V631302_RELAXED_MEMBER} does not match the exact zero-authority Amendment-9 working bundle")
    endif()
endforeach()

get_filename_component(V631302_RELAXED_PINNED_INTERPRETER
    "${Python3_EXECUTABLE}" REALPATH)
file(SIZE "${V631302_RELAXED_PINNED_INTERPRETER}" V631302_RELAXED_INTERPRETER_SIZE)
file(SHA256 "${V631302_RELAXED_PINNED_INTERPRETER}" V631302_RELAXED_INTERPRETER_SHA256)
execute_process(
    COMMAND "${V631302_RELAXED_PINNED_INTERPRETER}" -c
        "import sys; print(sys.hexversion); print(sys.implementation.cache_tag); print(sys.abiflags or '__V631302_EMPTY_ABI_FLAGS__')"
    RESULT_VARIABLE V631302_RELAXED_PYTHON_STATUS
    OUTPUT_VARIABLE V631302_RELAXED_PYTHON_IDENTITY
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT V631302_RELAXED_PYTHON_STATUS EQUAL 0)
    message(FATAL_ERROR "unable to identify the pinned relaxed-fixture interpreter")
endif()
string(REPLACE "\n" ";" V631302_RELAXED_PYTHON_ROWS "${V631302_RELAXED_PYTHON_IDENTITY}")
list(LENGTH V631302_RELAXED_PYTHON_ROWS V631302_RELAXED_PYTHON_COUNT)
if(NOT V631302_RELAXED_PYTHON_COUNT EQUAL 3)
    message(FATAL_ERROR "unexpected relaxed-fixture interpreter identity output")
endif()
list(GET V631302_RELAXED_PYTHON_ROWS 0 V631302_RELAXED_PYTHON_VERSION_HEX)
list(GET V631302_RELAXED_PYTHON_ROWS 1 V631302_RELAXED_PYTHON_CACHE_TAG)
list(GET V631302_RELAXED_PYTHON_ROWS 2 V631302_RELAXED_PYTHON_ABI_FLAGS)
if(V631302_RELAXED_PYTHON_ABI_FLAGS STREQUAL "__V631302_EMPTY_ABI_FLAGS__")
    set(V631302_RELAXED_PYTHON_ABI_FLAGS "")
endif()

# The execution profile is bound to one exact CPython binary.  A different
# interpreter must not create a self-consistent but protocol-incompatible pin.
if(NOT V631302_RELAXED_PINNED_INTERPRETER STREQUAL "/usr/bin/python3.11" OR
   NOT V631302_RELAXED_INTERPRETER_SIZE EQUAL 6834488 OR
   NOT V631302_RELAXED_INTERPRETER_SHA256 STREQUAL
       "6d972cf21be56fe3c947ab6ba257ff8d08c342dd2714442986791bd9a6dfabfe" OR
   NOT V631302_RELAXED_PYTHON_VERSION_HEX EQUAL 51053296 OR
   NOT V631302_RELAXED_PYTHON_CACHE_TAG STREQUAL "cpython-311" OR
   NOT V631302_RELAXED_PYTHON_ABI_FLAGS STREQUAL "")
    message(FATAL_ERROR "relaxed fixture requires the exact bound CPython 3.11.2 identity")
endif()

find_program(V631302_RELAXED_CLANG_PROGRAM
    NAMES clang-16 clang
    HINTS ${LLVM_TOOLS_BINARY_DIR}
    NO_DEFAULT_PATH
)
if(NOT V631302_RELAXED_CLANG_PROGRAM)
    message(FATAL_ERROR "unable to resolve pinned Clang 16 for relaxed fixture")
endif()
get_filename_component(V631302_RELAXED_PINNED_CLANG
    "${V631302_RELAXED_CLANG_PROGRAM}" REALPATH)
file(SIZE "${V631302_RELAXED_PINNED_CLANG}" V631302_RELAXED_CLANG_SIZE)
file(SHA256 "${V631302_RELAXED_PINNED_CLANG}" V631302_RELAXED_CLANG_SHA256)
execute_process(
    COMMAND "${V631302_RELAXED_PINNED_CLANG}" -dumpversion
    RESULT_VARIABLE V631302_RELAXED_CLANG_STATUS
    OUTPUT_VARIABLE V631302_RELAXED_CLANG_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT V631302_RELAXED_CLANG_STATUS EQUAL 0 OR
   NOT V631302_RELAXED_CLANG_VERSION MATCHES "^16(\\.|$)")
    message(FATAL_ERROR "relaxed fixture requires pinned Clang major 16")
endif()
if(NOT V631302_RELAXED_PINNED_CLANG STREQUAL "/opt/llvm-build/bin/clang-16" OR
   NOT V631302_RELAXED_CLANG_SIZE EQUAL 124243800 OR
   NOT V631302_RELAXED_CLANG_SHA256 STREQUAL
       "e5a7f6f0d3449c783a60d612ae4a5f2ef26570438e96bc902481bd78e8484e27" OR
   NOT V631302_RELAXED_CLANG_VERSION STREQUAL "16.0.6")
    message(FATAL_ERROR "relaxed fixture requires the exact bound Clang 16.0.6 identity")
endif()

set(V631302_RELAXED_BUILD_ID "V631302_RELAXED_FD_EMULATION_FIXTURE_V1")
configure_file(
    ExecutionOriginRelaxedBuildConfig.h.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/ExecutionOriginRelaxedBuildConfig.h"
    @ONLY
)

find_library(V631302_RELAXED_LLVM_DYLIB
    NAMES LLVM-16 LLVM
    HINTS ${LLVM_LIBRARY_DIRS}
    NO_DEFAULT_PATH
)

add_executable(v631302-m0-diagnostic-relaxed-fd-fixture
    ExecutionOriginRelaxed.cpp
    FreshWorkerRelaxedMain.cpp
)
target_compile_features(v631302-m0-diagnostic-relaxed-fd-fixture PRIVATE cxx_std_20)
target_compile_options(v631302-m0-diagnostic-relaxed-fd-fixture PRIVATE
    -Wall -Wextra -Werror -Wpedantic
)
target_include_directories(v631302-m0-diagnostic-relaxed-fd-fixture SYSTEM PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
)
target_include_directories(v631302-m0-diagnostic-relaxed-fd-fixture PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
)
target_compile_definitions(v631302-m0-diagnostic-relaxed-fd-fixture PRIVATE ${LLVM_DEFINITIONS})
target_link_libraries(v631302-m0-diagnostic-relaxed-fd-fixture PRIVATE clang-cpp)
if(V631302_RELAXED_LLVM_DYLIB)
    target_link_libraries(v631302-m0-diagnostic-relaxed-fd-fixture PRIVATE
        ${V631302_RELAXED_LLVM_DYLIB}
    )
endif()
set_target_properties(v631302-m0-diagnostic-relaxed-fd-fixture PROPERTIES
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
