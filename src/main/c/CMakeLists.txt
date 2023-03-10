cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(pcap-native LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_subdirectory(libpcap)
set_property(TARGET pcap PROPERTY SOVERSION)
set_property(TARGET pcap PROPERTY VERSION)

set(LIB_OUTPUT_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${LIB_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_OUTPUT_DIR})

find_package(Java REQUIRED)
set(JAVA_AWT_LIBRARY NotNeeded)
set(JAVA_JVM_LIBRARY NotNeeded)
find_package(JNI REQUIRED)

include_directories(${JNI_INCLUDE_DIRS})

if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "
    CMake generation is not allowed within the source directory!
    Remove the CMakeCache.txt file and try again from another folder, e.g.:
    mkdir build && cd build
    cmake ..
  ")
endif()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_RELEASE "-O2 -Wall -Werror")

include_directories(include)
include_directories(libpcap)

add_library(pcap-native SHARED src/pcap.c src/pcap_javacritical.c)
target_link_libraries(pcap-native pcap)

add_library(pcap-init SHARED src/pcap_init.c)
target_link_libraries(pcap-init pcap)