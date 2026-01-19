# CMake generated Testfile for 
# Source directory: /tmp/binary-fuzz-engine_1773305854
# Build directory: /tmp/binary-fuzz-engine_1773305854/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(FuzzerTests "/tmp/binary-fuzz-engine_1773305854/build/test_fuzzer")
set_tests_properties(FuzzerTests PROPERTIES  _BACKTRACE_TRIPLES "/tmp/binary-fuzz-engine_1773305854/CMakeLists.txt;45;add_test;/tmp/binary-fuzz-engine_1773305854/CMakeLists.txt;0;")
add_test(RawFuzzTest "/tmp/binary-fuzz-engine_1773305854/build/binary-fuzz-engine" "-m" "raw" "-i" "100" "-s" "42")
set_tests_properties(RawFuzzTest PROPERTIES  _BACKTRACE_TRIPLES "/tmp/binary-fuzz-engine_1773305854/CMakeLists.txt;47;add_test;/tmp/binary-fuzz-engine_1773305854/CMakeLists.txt;0;")
add_test(ProtocolFuzzTest "/tmp/binary-fuzz-engine_1773305854/build/binary-fuzz-engine" "-m" "protocol" "-i" "100" "-s" "42")
set_tests_properties(ProtocolFuzzTest PROPERTIES  _BACKTRACE_TRIPLES "/tmp/binary-fuzz-engine_1773305854/CMakeLists.txt;50;add_test;/tmp/binary-fuzz-engine_1773305854/CMakeLists.txt;0;")
