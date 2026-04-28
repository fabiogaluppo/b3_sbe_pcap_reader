cmake_minimum_required(VERSION 3.20)

project(b3_sbe_pcap_reader LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-error=restrict)
endif()

if (MSVC)
    add_compile_definitions(
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

add_subdirectory(external/PcapPlusPlus)

add_executable(b3_sbe_pcap_reader
    main.cpp
)

target_link_libraries(b3_sbe_pcap_reader
    PRIVATE
        Pcap++
        Packet++
        Common++
)