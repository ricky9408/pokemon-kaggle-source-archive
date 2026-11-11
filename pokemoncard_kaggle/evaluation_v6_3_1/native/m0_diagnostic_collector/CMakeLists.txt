cmake_minimum_required(VERSION 3.20)
project(v631302_m0_diagnostic_collector LANGUAGES C CXX)

# Binding 10 requires a distinct target.  Do not add sources from
# native/state3_extractor here: that binary and its limited closure are frozen.
find_package(LLVM 16.0.6 REQUIRED CONFIG)
find_package(Clang 16.0.6 REQUIRED CONFIG)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

option(V631302_M0_DIAGNOSTIC_ENABLE_TEST_BOOTSTRAP
    "Build only the zero-authority fresh-worker substrate test bootstrap" OFF)
option(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS
    "Enable zero-authority structural-path contract test modes" OFF)
set(V631302_M0_DIAGNOSTIC_TEST_BOOTSTRAP_PATH "" CACHE FILEPATH
    "Pinned test-only worker bootstrap source")

get_filename_component(V631302_M0_PINNED_INTERPRETER
    "${Python3_EXECUTABLE}" REALPATH)
find_program(V631302_M0_CLANG_PROGRAM
    NAMES clang-16 clang
    HINTS ${LLVM_TOOLS_BINARY_DIR}
    NO_DEFAULT_PATH
)
if(NOT V631302_M0_CLANG_PROGRAM)
    message(FATAL_ERROR "unable to resolve the pinned Clang executable from LLVM 16")
endif()
get_filename_component(V631302_M0_PINNED_CLANG
    "${V631302_M0_CLANG_PROGRAM}" REALPATH)
file(SIZE "${V631302_M0_PINNED_CLANG}" V631302_M0_CLANG_SIZE)
file(SHA256 "${V631302_M0_PINNED_CLANG}" V631302_M0_CLANG_SHA256)
execute_process(
    COMMAND "${V631302_M0_PINNED_CLANG}" -dumpversion
    RESULT_VARIABLE V631302_M0_CLANG_VERSION_STATUS
    OUTPUT_VARIABLE V631302_M0_CLANG_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT V631302_M0_CLANG_VERSION_STATUS EQUAL 0)
    message(FATAL_ERROR "unable to query the pinned Clang major version")
endif()
string(REGEX MATCH "^[0-9]+" V631302_M0_CLANG_MAJOR "${V631302_M0_CLANG_VERSION}")
if(V631302_M0_CLANG_MAJOR STREQUAL "")
    message(FATAL_ERROR "unable to derive the pinned Clang major version")
endif()
file(SIZE "${V631302_M0_PINNED_INTERPRETER}" V631302_M0_INTERPRETER_SIZE)
file(SHA256 "${V631302_M0_PINNED_INTERPRETER}" V631302_M0_INTERPRETER_SHA256)
execute_process(
    COMMAND "${V631302_M0_PINNED_INTERPRETER}" -c
        "import sys; print(sys.hexversion); print(sys.implementation.cache_tag); print(sys.abiflags or '__V631302_EMPTY_ABI_FLAGS__')"
    RESULT_VARIABLE V631302_M0_PYTHON_IDENTITY_STATUS
    OUTPUT_VARIABLE V631302_M0_PYTHON_IDENTITY
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT V631302_M0_PYTHON_IDENTITY_STATUS EQUAL 0)
    message(FATAL_ERROR "unable to query build-pinned CPython interpreter")
endif()
string(REPLACE "\n" ";" V631302_M0_PYTHON_IDENTITY_ROWS "${V631302_M0_PYTHON_IDENTITY}")
list(LENGTH V631302_M0_PYTHON_IDENTITY_ROWS V631302_M0_PYTHON_IDENTITY_COUNT)
if(NOT V631302_M0_PYTHON_IDENTITY_COUNT EQUAL 3)
    message(FATAL_ERROR "unexpected build-pinned CPython identity output")
endif()
list(GET V631302_M0_PYTHON_IDENTITY_ROWS 0 V631302_M0_PYTHON_VERSION_HEX)
list(GET V631302_M0_PYTHON_IDENTITY_ROWS 1 V631302_M0_PYTHON_CACHE_TAG)
list(GET V631302_M0_PYTHON_IDENTITY_ROWS 2 V631302_M0_PYTHON_ABI_FLAGS)
if(V631302_M0_PYTHON_ABI_FLAGS STREQUAL "__V631302_EMPTY_ABI_FLAGS__")
    set(V631302_M0_PYTHON_ABI_FLAGS "")
endif()

set(V631302_M0_TEST_BOOTSTRAP_ENABLED 0)
set(V631302_M0_TEST_BOOTSTRAP_SIZE 0)
set(V631302_M0_TEST_BOOTSTRAP_SHA256 "")
if(V631302_M0_DIAGNOSTIC_ENABLE_TEST_BOOTSTRAP)
    if(NOT IS_ABSOLUTE "${V631302_M0_DIAGNOSTIC_TEST_BOOTSTRAP_PATH}" OR
       NOT EXISTS "${V631302_M0_DIAGNOSTIC_TEST_BOOTSTRAP_PATH}")
        message(FATAL_ERROR "test bootstrap path must be an existing absolute path")
    endif()
    file(SIZE "${V631302_M0_DIAGNOSTIC_TEST_BOOTSTRAP_PATH}" V631302_M0_TEST_BOOTSTRAP_SIZE)
    file(SHA256 "${V631302_M0_DIAGNOSTIC_TEST_BOOTSTRAP_PATH}" V631302_M0_TEST_BOOTSTRAP_SHA256)
    set(V631302_M0_TEST_BOOTSTRAP_ENABLED 1)
endif()
# This stable test-profile field is intentionally distinct from an eventual
# production collector build identifier.  The test target remains zero
# authority and cannot produce a campaign artifact.
set(V631302_M0_COLLECTOR_BUILD_ID "V631302_M0_DIAGNOSTIC_LEVEL2_TEST_V1")
configure_file(
    ExecutionOriginBuildConfig.h.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/ExecutionOriginBuildConfig.h"
    @ONLY
)
find_library(V631302_LLVM_DYLIB
    NAMES LLVM-16 LLVM
    HINTS ${LLVM_LIBRARY_DIRS}
    NO_DEFAULT_PATH
)

add_executable(v631302-m0-diagnostic-collector
    RawCborWriter.cpp
    ../capture_v2/CollectorReceipt.cpp
    M0DiagnosticCollector.cpp
)

target_compile_features(v631302-m0-diagnostic-collector PRIVATE cxx_std_20)
target_compile_options(v631302-m0-diagnostic-collector PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wpedantic
)
target_include_directories(v631302-m0-diagnostic-collector SYSTEM PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
)
target_include_directories(v631302-m0-diagnostic-collector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../capture_v2
)
target_compile_definitions(v631302-m0-diagnostic-collector PRIVATE ${LLVM_DEFINITIONS})
if(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    target_compile_definitions(v631302-m0-diagnostic-collector PRIVATE
        V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS=1)
endif()
target_link_libraries(v631302-m0-diagnostic-collector PRIVATE clang-cpp)
if(V631302_LLVM_DYLIB)
    target_link_libraries(v631302-m0-diagnostic-collector PRIVATE ${V631302_LLVM_DYLIB})
endif()

set_target_properties(v631302-m0-diagnostic-collector PROPERTIES
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
if(V631302_M0_DIAGNOSTIC_ENABLE_TEST_BOOTSTRAP)
    # This is intentionally a distinct test-only executable.  It validates the
    # native fresh-worker substrate but is not the missing DIAGNOSTIC_CENSUS_V1
    # canonicalizer and cannot emit a campaign artifact or authority decision.
    add_executable(v631302-m0-diagnostic-fresh-worker
        RawCborWriter.cpp
        ExecutionOrigin.cpp
        FreshWorkerMain.cpp
    )
    target_compile_features(v631302-m0-diagnostic-fresh-worker PRIVATE cxx_std_20)
    target_compile_options(v631302-m0-diagnostic-fresh-worker PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wpedantic
    )
    target_include_directories(v631302-m0-diagnostic-fresh-worker SYSTEM PRIVATE
        ${LLVM_INCLUDE_DIRS}
        ${CLANG_INCLUDE_DIRS}
    )
    target_include_directories(v631302-m0-diagnostic-fresh-worker PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
    )
    target_compile_definitions(v631302-m0-diagnostic-fresh-worker PRIVATE ${LLVM_DEFINITIONS})
    target_link_libraries(v631302-m0-diagnostic-fresh-worker PRIVATE clang-cpp)
    set_target_properties(v631302-m0-diagnostic-fresh-worker PROPERTIES
        CXX_EXTENSIONS OFF
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()
