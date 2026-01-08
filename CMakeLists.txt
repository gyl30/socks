cmake_minimum_required(VERSION 3.16)
project(socks VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer -g -O0 -ggdb")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-strict-aliasing -fno-omit-frame-pointer -g -O0 -ggdb")

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_DEBUG_LIBS ON)
set(Boost_USE_RELEASE_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost 1.85.0)
include_directories(${Boost_INCLUDE_DIRS})
message(STATUS "Found Boost:    V${Boost_VERSION} (in ${Boost_DIR})")

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(FUZZ OFF CACHE BOOL "" FORCE)
set(RUST_BINDINGS OFF CACHE BOOL "" FORCE)
set(INSTALL_ENABLED 0 CACHE BOOL "" FORCE)
add_subdirectory(third/boringssl EXCLUDE_FROM_ALL)

add_executable(socks main.cpp log.cpp)

target_include_directories(socks PRIVATE ${Boost_INCLUDE_DIRS} third/spdlog/include)

target_link_libraries(socks PRIVATE ${Boost_LIBRARIES} ssl crypto)
