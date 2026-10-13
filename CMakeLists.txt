# ESP-IDF picks up this file as a component. Other CMake projects get a plain
# static library. The host test build uses the Makefile.

if(ESP_PLATFORM)
    idf_component_register(SRC_DIRS "src"
                           INCLUDE_DIRS "include")
    return()
endif()

cmake_minimum_required(VERSION 3.16)
project(transponder C)

file(GLOB TRANSPONDER_SOURCES CONFIGURE_DEPENDS src/*.c)
add_library(transponder STATIC ${TRANSPONDER_SOURCES})
target_include_directories(transponder PUBLIC include)
set_target_properties(transponder PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
