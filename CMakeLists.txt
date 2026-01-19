cmake_minimum_required(VERSION 3.10)
project(binary-fuzz-engine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_options(-O2)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-Wno-maybe-uninitialized)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

set(FUZZER_SOURCES
    src/fuzzer.cpp
    src/protocol.cpp
)

set(FUZZER_HEADERS
    include/fuzzer.h
    include/protocol.h
)

add_library(fuzzer_lib STATIC ${FUZZER_SOURCES} ${FUZZER_HEADERS})
target_include_directories(fuzzer_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(binary-fuzz-engine src/main.cpp)
target_link_libraries(binary-fuzz-engine PRIVATE fuzzer_lib)

option(BUILD_TESTS "Build test suite" ON)

if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_fuzzer tests/test_fuzzer.cpp)
    target_link_libraries(test_fuzzer PRIVATE fuzzer_lib)
    
    add_test(NAME FuzzerTests COMMAND test_fuzzer)
    
    add_test(NAME RawFuzzTest 
        COMMAND ${CMAKE_BINARY_DIR}/binary-fuzz-engine -m raw -i 100 -s 42)
    
    add_test(NAME ProtocolFuzzTest 
        COMMAND ${CMAKE_BINARY_DIR}/binary-fuzz-engine -m protocol -i 100 -s 42)
endif()

install(TARGETS binary-fuzz-engine DESTINATION bin)
install(FILES include/fuzzer.h include/protocol.h DESTINATION include)

set(CPACK_PACKAGE_NAME "binary-fuzz-engine")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Low-level binary protocol fuzzing engine")
include(CPack)
