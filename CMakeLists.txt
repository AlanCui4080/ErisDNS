cmake_minimum_required(VERSION 3.31)

project(ErisDNS
    VERSION 0.0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Boost REQUIRED)

set(ERISDNS_SOURCES
    src/dns_types.cpp
    src/dns_parser.cpp
    src/dns_resolver.cpp
    src/dns_cache.cpp
    src/dns_upstream.cpp
    src/dns_recursive.cpp
    src/dns_server.cpp
    src/main.cpp
)

add_executable(erisdns ${ERISDNS_SOURCES})
target_include_directories(erisdns PRIVATE include)
target_link_libraries(erisdns PRIVATE Boost::headers)

# Tests
enable_testing()
find_package(Boost REQUIRED COMPONENTS unit_test_framework)

add_executable(test_parser test/test_parser.cpp src/dns_types.cpp src/dns_parser.cpp src/dns_resolver.cpp)
target_include_directories(test_parser PRIVATE include)
target_link_libraries(test_parser PRIVATE Boost::unit_test_framework Boost::headers)
add_test(NAME test_parser COMMAND test_parser)

add_executable(test_negative test/test_negative.cpp src/dns_types.cpp src/dns_parser.cpp src/dns_resolver.cpp)
target_include_directories(test_negative PRIVATE include)
target_link_libraries(test_negative PRIVATE Boost::unit_test_framework Boost::headers)
add_test(NAME test_negative COMMAND test_negative)

add_executable(test_class test/test_class.cpp src/dns_types.cpp src/dns_parser.cpp src/dns_resolver.cpp)
target_include_directories(test_class PRIVATE include)
target_link_libraries(test_class PRIVATE Boost::unit_test_framework Boost::headers)
add_test(NAME test_class COMMAND test_class)

add_executable(test_product test/test_product.cpp src/dns_types.cpp src/dns_parser.cpp src/dns_resolver.cpp src/dns_cache.cpp src/dns_upstream.cpp src/dns_recursive.cpp src/dns_server.cpp)
target_include_directories(test_product PRIVATE include)
target_link_libraries(test_product PRIVATE Boost::unit_test_framework Boost::headers)
add_test(NAME test_product COMMAND test_product)

add_executable(test_semi_fuzz test/test_semi_fuzz.cpp src/dns_types.cpp src/dns_parser.cpp src/dns_resolver.cpp)
target_include_directories(test_semi_fuzz PRIVATE include)
target_link_libraries(test_semi_fuzz PRIVATE Boost::unit_test_framework Boost::headers)
add_test(NAME test_semi_fuzz COMMAND test_semi_fuzz)

# Fuzz test using clang's libFuzzer
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(fuzz_parser EXCLUDE_FROM_ALL test/fuzz_parser.cpp src/dns_types.cpp src/dns_parser.cpp src/dns_resolver.cpp)
    target_include_directories(fuzz_parser PRIVATE include)
    target_compile_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
