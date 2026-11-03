cmake_minimum_required(VERSION 3.16)
project(PacketSniffer VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PACKETSNIFFER_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer for local testing" OFF)
if(PACKETSNIFFER_ENABLE_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "Sanitizer builds require a Clang- or GCC-compatible compiler.")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap development headers and library are required.")
endif()

add_library(packet_sniffer_core
    src/CliOptions.cpp
    src/PacketParser.cpp
    src/PacketFormatter.cpp
)
target_include_directories(packet_sniffer_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${PCAP_INCLUDE_DIR}"
)
target_link_libraries(packet_sniffer_core PUBLIC "${PCAP_LIBRARY}")

add_executable(packetSniffer src/main.cpp src/PacketCapture.cpp)
target_link_libraries(packetSniffer PRIVATE packet_sniffer_core)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(packet_sniffer_core PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(packetSniffer PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(phase1_safety_smoke tests/phase1_safety_smoke.cpp)
    target_link_libraries(phase1_safety_smoke PRIVATE packet_sniffer_core)
    add_test(NAME phase1_safety_smoke COMMAND phase1_safety_smoke)

    add_executable(cli_options_smoke tests/cli_options_smoke.cpp)
    target_link_libraries(cli_options_smoke PRIVATE packet_sniffer_core)
    add_test(NAME cli_options_smoke COMMAND cli_options_smoke)

    add_executable(parser_adversarial tests/parser_adversarial.cpp)
    target_link_libraries(parser_adversarial PRIVATE packet_sniffer_core)
    add_test(NAME parser_adversarial COMMAND parser_adversarial)

    add_executable(pcap_fixture_regressions tests/pcap_fixture_regressions.cpp)
    target_link_libraries(pcap_fixture_regressions PRIVATE packet_sniffer_core)
    add_test(NAME pcap_fixture_regressions COMMAND pcap_fixture_regressions
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/synthetic_mixed_traffic.pcap")
endif()
