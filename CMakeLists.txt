cmake_minimum_required(VERSION 3.11)
project(CVE_2023_28252 LANGUAGES CXX)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_INCLUDE

    include/common/environment.hpp
    include/common/shellcode.hpp
    include/common/memtools.hpp
    include/common/gadget.hpp
)
set(PROJECT_SOURCE
    src/main.cpp

    src/common/environment.cpp
    src/common/shellcode.cpp
    src/common/memtools.cpp
    src/common/gadget.cpp
)
set(EXPLOIT
    exp/CVE_2023_28252/def.hpp
    exp/CVE_2023_28252/def.cpp
    exp/CVE_2023_28252/exp.hpp
    exp/CVE_2023_28252/exp.cpp
    exp/CVE_2023_28252/poc.hpp
    exp/CVE_2023_28252/poc.cpp
    exp/CVE_2023_28252/clfs_types.h

)

# Specify MSVC UTF-8 encoding
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
link_libraries("clfsw32.lib")
add_executable(${PROJECT_NAME} ${PROJECT_INCLUDE} ${PROJECT_SOURCE} ${EXPLOIT})
target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)