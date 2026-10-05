cmake_minimum_required(VERSION 3.16)
project(tylogin_native CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(UNICORN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/unicorn)

# unicorn 构建
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(UNICORN_ARCH "aarch64" CACHE STRING "" FORCE)
set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(${UNICORN_DIR} ${CMAKE_BINARY_DIR}/unicorn EXCLUDE_FROM_ALL)

# embed resources/libdaproxy.so -> gen/libdaproxy_so.h
find_program(EMBED_PYTHON NAMES python3 python)
set(GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)
file(MAKE_DIRECTORY ${GEN_DIR})
add_custom_command(
    OUTPUT ${GEN_DIR}/libdaproxy_so.h
    COMMAND ${EMBED_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed.py
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/libdaproxy.so
            ${GEN_DIR}/libdaproxy_so.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/resources/libdaproxy.so
    COMMENT "embedding libdaproxy.so"
)
add_custom_target(embed_resource DEPENDS ${GEN_DIR}/libdaproxy_so.h)

add_executable(tylogin
    src/main.cpp
    src/dialer.cpp
    src/http.cpp
    src/md5.cpp
    src/util.cpp
    src/zsm/emu.cpp
    src/zsm/elfload.cpp
    src/zsm/guestlibc.cpp
    src/zsm/jni.cpp
    src/zsm/damod.cpp
)

add_dependencies(tylogin embed_resource)
target_include_directories(tylogin PRIVATE
    src
    ${GEN_DIR}
)
if(WIN32)
    # single-file exe: no libstdc++/libgcc/winpthread runtime DLLs needed
    target_link_options(tylogin PRIVATE -static)
    target_link_libraries(tylogin PRIVATE unicorn unicorn-common ws2_32 winmm)
else()
    target_link_libraries(tylogin PRIVATE unicorn unicorn-common pthread m)
endif()
target_compile_options(tylogin PRIVATE -Wall -Wextra)
