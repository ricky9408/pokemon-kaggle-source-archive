cmake_minimum_required(VERSION 3.20)
project(v631302_native_extractor LANGUAGES C CXX)

find_package(LLVM 16.0.6 REQUIRED CONFIG)
find_package(Clang 16.0.6 REQUIRED CONFIG)
find_library(V631302_LLVM_DYLIB
    NAMES LLVM-16 LLVM
    HINTS ${LLVM_LIBRARY_DIRS}
    NO_DEFAULT_PATH
)

add_executable(v631302-native-extractor
    CborWriter.cpp
    Observation.cpp
    State3Extractor.cpp
)

target_compile_features(v631302-native-extractor PRIVATE cxx_std_20)
target_compile_options(v631302-native-extractor PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wpedantic
)
target_include_directories(v631302-native-extractor SYSTEM PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
)
target_compile_definitions(v631302-native-extractor PRIVATE ${LLVM_DEFINITIONS})
target_link_libraries(v631302-native-extractor PRIVATE clang-cpp)
if(V631302_LLVM_DYLIB)
    target_link_libraries(v631302-native-extractor PRIVATE ${V631302_LLVM_DYLIB})
endif()

set_target_properties(v631302-native-extractor PROPERTIES
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
