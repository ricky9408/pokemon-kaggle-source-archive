cmake_minimum_required(VERSION 3.20)
project(v631302_relaxed_boundary_harness LANGUAGES CXX)

find_package(LLVM 16.0.6 REQUIRED CONFIG)
find_package(Clang 16.0.6 REQUIRED CONFIG)

if(NOT DEFINED V631302_RELAXED_GENERATED_INCLUDE OR
   NOT IS_ABSOLUTE "${V631302_RELAXED_GENERATED_INCLUDE}")
    message(FATAL_ERROR "V631302_RELAXED_GENERATED_INCLUDE must be absolute")
endif()

find_library(V631302_HARNESS_LLVM_DYLIB
    NAMES LLVM-16 LLVM
    HINTS ${LLVM_LIBRARY_DIRS}
    NO_DEFAULT_PATH
)

add_executable(v631302-relaxed-boundary-harness
    ../v631302_relaxed_boundary_harness.cpp
)
target_compile_features(v631302-relaxed-boundary-harness PRIVATE cxx_std_20)
target_compile_options(v631302-relaxed-boundary-harness PRIVATE
    -Wall -Wextra -Werror -Wpedantic
)
target_include_directories(v631302-relaxed-boundary-harness SYSTEM PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
)
target_include_directories(v631302-relaxed-boundary-harness PRIVATE
    "${V631302_RELAXED_GENERATED_INCLUDE}"
)
target_compile_definitions(v631302-relaxed-boundary-harness PRIVATE ${LLVM_DEFINITIONS})
target_link_libraries(v631302-relaxed-boundary-harness PRIVATE clang-cpp)
if(V631302_HARNESS_LLVM_DYLIB)
    target_link_libraries(v631302-relaxed-boundary-harness PRIVATE
        ${V631302_HARNESS_LLVM_DYLIB}
    )
endif()
set_target_properties(v631302-relaxed-boundary-harness PROPERTIES
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
